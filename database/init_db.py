import os
import sqlite3
from datetime import datetime, timedelta
from urllib.parse import quote_plus, urlencode

import yaml

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "protective_intel.db")
LEGACY_DB_PATH = os.path.join(os.path.dirname(__file__), "osint_monitor.db")
DB_PATH = DEFAULT_DB_PATH
WATCHLIST_CONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "watchlist.yaml")
)

SOURCE_DEFAULT_CREDIBILITY = {
    "rss": 0.8,
    "reddit": 0.5,
    "pastebin": 0.2,
    "darkweb": 0.2,
}

GDELT_DOC_API_BASE_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
DEFAULT_GDELT_PI_EP_QUERY = (
    '("threat to CEO" OR swatting OR doxxing OR "death threat" OR kidnapping OR "bomb threat" OR protest OR unrest) '
    'AND (executive OR CEO OR headquarters OR office OR venue)'
)

KEYWORD_CATEGORY_ALIASES = {
    "protest": "protest_disruption",
    "facility_risk": "protective_intel",
    "person_of_interest": "poi",
    "people_of_interest": "poi",
    "workplace": "insider_workplace",
    "travel": "travel_risk",
}

KEYWORD_DEFAULT_WEIGHTS_BY_CATEGORY = {
    "poi": 4.0,
    "protective_intel": 3.8,
    "protest_disruption": 2.0,
    "travel_risk": 2.5,
    "insider_workplace": 2.5,
    "ioc": 1.2,
}


def get_connection():
    db_path = _resolve_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Database initialized at {_resolve_db_path()}")


def _resolve_db_path():
    # Respect explicit overrides (e.g., tests monkeypatching DB_PATH).
    if DB_PATH != DEFAULT_DB_PATH:
        return DB_PATH
    if os.path.exists(DEFAULT_DB_PATH):
        return DEFAULT_DB_PATH
    if os.path.exists(LEGACY_DB_PATH):
        return LEGACY_DB_PATH
    return DEFAULT_DB_PATH


def _get_table_columns(conn, table_name):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()]


def _create_alert_entities_v2(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS alert_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(alert_id, entity_type, entity_value),
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        )"""
    )


def _migrate_alert_entities_table(conn):
    """
    Ensure alert_entities matches flat IOC-entity schema.
    """
    existing = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alert_entities'"
    ).fetchone()
    if not existing:
        _create_alert_entities_v2(conn)
        return

    cols = set(_get_table_columns(conn, "alert_entities"))
    expected = {"id", "alert_id", "entity_type", "entity_value", "created_at"}
    if expected.issubset(cols):
        return

    conn.execute("ALTER TABLE alert_entities RENAME TO alert_entities_legacy")
    _create_alert_entities_v2(conn)

    legacy_cols = set(_get_table_columns(conn, "alert_entities_legacy"))
    if {"alert_id", "entity_type", "entity_value"}.issubset(legacy_cols):
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities
            (alert_id, entity_type, entity_value, created_at)
            SELECT alert_id, entity_type, entity_value, COALESCE(created_at, CURRENT_TIMESTAMP)
            FROM alert_entities_legacy"""
        )


def _parse_sqlite_datetime(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace("T", " ")
    if normalized.endswith("Z"):
        normalized = normalized[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _canonicalize_assessment_window(start_dt, end_dt):
    if end_dt is None:
        return None
    if end_dt.time() == datetime.min.time():
        canonical_end = end_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        canonical_end = end_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)

    if start_dt is not None:
        raw_days = (end_dt - start_dt).total_seconds() / 86400.0
        duration_days = max(1, int(round(raw_days)))
    else:
        duration_days = 14
    canonical_start = canonical_end - timedelta(days=duration_days)
    return canonical_start, canonical_end, duration_days


def _compact_legacy_poi_assessments(conn):
    """Collapse pre-stabilization POI assessment duplicates into daily windows."""
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'poi_assessments'"
    ).fetchone()
    if not exists:
        return 0

    rows = conn.execute(
        """SELECT id, poi_id, window_start, window_end, created_at
        FROM poi_assessments
        ORDER BY datetime(created_at) DESC, id DESC"""
    ).fetchall()
    if len(rows) <= 1:
        return 0

    keep_by_key = {}
    canonical_bounds = {}
    delete_ids = []

    for row in rows:
        start_dt = _parse_sqlite_datetime(row["window_start"])
        end_dt = _parse_sqlite_datetime(row["window_end"])
        canonical = _canonicalize_assessment_window(start_dt, end_dt)
        if canonical is None:
            key = ("raw", int(row["poi_id"]), str(row["window_start"]), str(row["window_end"]))
            start_str = str(row["window_start"])
            end_str = str(row["window_end"])
        else:
            canonical_start, canonical_end, duration_days = canonical
            key = (
                int(row["poi_id"]),
                int(duration_days),
                canonical_end.strftime("%Y-%m-%d"),
            )
            start_str = canonical_start.strftime("%Y-%m-%d %H:%M:%S")
            end_str = canonical_end.strftime("%Y-%m-%d %H:%M:%S")

        if key in keep_by_key:
            delete_ids.append(int(row["id"]))
            continue

        row_id = int(row["id"])
        keep_by_key[key] = row_id
        canonical_bounds[row_id] = (start_str, end_str)

    if delete_ids:
        placeholders = ",".join("?" for _ in delete_ids)
        conn.execute(f"DELETE FROM poi_assessments WHERE id IN ({placeholders})", delete_ids)

    for row_id, (start_str, end_str) in canonical_bounds.items():
        current = conn.execute(
            "SELECT window_start, window_end FROM poi_assessments WHERE id = ?",
            (row_id,),
        ).fetchone()
        if not current:
            continue
        if current["window_start"] == start_str and current["window_end"] == end_str:
            continue
        try:
            conn.execute(
                "UPDATE poi_assessments SET window_start = ?, window_end = ? WHERE id = ?",
                (start_str, end_str, row_id),
            )
        except sqlite3.IntegrityError:
            # Another normalized row already occupies this unique key.
            conn.execute("DELETE FROM poi_assessments WHERE id = ?", (row_id,))
            delete_ids.append(row_id)

    return len(delete_ids)


def _ensure_schema_migrations_table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )


def _has_schema_migration(conn, name):
    row = conn.execute("SELECT 1 FROM schema_migrations WHERE name = ?", (name,)).fetchone()
    return row is not None


def _mark_schema_migration(conn, name):
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?, CURRENT_TIMESTAMP)",
        (name,),
    )


def migrate_schema():
    """Add new columns to existing tables. Safe to run multiple times."""
    conn = get_connection()
    migrations = [
        "ALTER TABLE keywords ADD COLUMN weight REAL DEFAULT 1.0",
        "ALTER TABLE keywords ADD COLUMN weight_sigma REAL",
        "ALTER TABLE sources ADD COLUMN credibility_score REAL DEFAULT 0.5",
        "ALTER TABLE sources ADD COLUMN true_positives INTEGER DEFAULT 0",
        "ALTER TABLE sources ADD COLUMN false_positives INTEGER DEFAULT 0",
        "ALTER TABLE sources ADD COLUMN bayesian_alpha REAL DEFAULT 2.0",
        "ALTER TABLE sources ADD COLUMN bayesian_beta REAL DEFAULT 2.0",
        "ALTER TABLE alerts ADD COLUMN risk_score REAL DEFAULT 0.0",
        "ALTER TABLE alerts ADD COLUMN content_hash TEXT",
        "ALTER TABLE alerts ADD COLUMN duplicate_of INTEGER",
        "ALTER TABLE alerts ADD COLUMN published_at TIMESTAMP",
        "ALTER TABLE alerts ADD COLUMN ors_score REAL DEFAULT 0.0",
        "ALTER TABLE alerts ADD COLUMN tas_score REAL DEFAULT 0.0",
        "ALTER TABLE alert_scores ADD COLUMN z_score REAL DEFAULT 0.0",
        "ALTER TABLE alert_scores ADD COLUMN category_factor REAL DEFAULT 0.0",
        "ALTER TABLE alert_scores ADD COLUMN proximity_factor REAL DEFAULT 0.0",
        "ALTER TABLE alert_scores ADD COLUMN event_factor REAL DEFAULT 0.0",
        "ALTER TABLE alert_scores ADD COLUMN poi_factor REAL DEFAULT 0.0",
        "ALTER TABLE threat_actors ADD COLUMN alert_count INTEGER DEFAULT 0",
        "ALTER TABLE intelligence_reports ADD COLUMN top_entities TEXT",
        "ALTER TABLE intelligence_reports ADD COLUMN new_cves TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists

    _migrate_alert_entities_table(conn)

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS pois (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            org TEXT,
            role TEXT,
            sensitivity INTEGER DEFAULT 3,
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS poi_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poi_id INTEGER NOT NULL,
            alias TEXT NOT NULL,
            alias_type TEXT DEFAULT 'name',
            active INTEGER DEFAULT 1,
            UNIQUE(poi_id, alias),
            FOREIGN KEY (poi_id) REFERENCES pois(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS poi_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poi_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            match_type TEXT NOT NULL,
            match_value TEXT NOT NULL,
            match_score REAL NOT NULL,
            context TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(poi_id, alert_id, match_value),
            FOREIGN KEY (poi_id) REFERENCES pois(id) ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS protected_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT,
            lat REAL,
            lon REAL,
            radius_miles REAL DEFAULT 5.0,
            active INTEGER DEFAULT 1,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alert_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            location_text TEXT NOT NULL,
            lat REAL,
            lon REAL,
            resolver TEXT,
            confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS alert_proximity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            protected_location_id INTEGER NOT NULL,
            distance_miles REAL,
            within_radius INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(alert_id, protected_location_id),
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
            FOREIGN KEY (protected_location_id) REFERENCES protected_locations(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT,
            start_dt TEXT NOT NULL,
            end_dt TEXT NOT NULL,
            city TEXT,
            country TEXT,
            venue TEXT,
            lat REAL,
            lon REAL,
            poi_id INTEGER,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (poi_id) REFERENCES pois(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS event_risk_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            computed_at TEXT NOT NULL,
            ors_mean REAL NOT NULL,
            ors_p95 REAL NOT NULL,
            top_drivers_json TEXT,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS dispositions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            rationale TEXT,
            user TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS retention_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            rows_affected INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            duration_ms REAL DEFAULT 0.0,
            actor TEXT,
            client_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS geocode_cache (
            query TEXT PRIMARY KEY,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            provider TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS poi_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poi_id INTEGER NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            fixation INTEGER DEFAULT 0,
            energy_burst INTEGER DEFAULT 0,
            leakage INTEGER DEFAULT 0,
            pathway INTEGER DEFAULT 0,
            targeting_specificity INTEGER DEFAULT 0,
            tas_score REAL NOT NULL,
            evidence_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(poi_id, window_start, window_end),
            FOREIGN KEY (poi_id) REFERENCES pois(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS travel_briefs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            destination TEXT NOT NULL,
            start_dt TEXT NOT NULL,
            end_dt TEXT NOT NULL,
            content_md TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS threat_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            aliases TEXT DEFAULT '[]',
            linked_poi_id INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'active',
            risk_tier TEXT DEFAULT 'LOW',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (linked_poi_id) REFERENCES pois(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS threat_subject_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            assessment_date TEXT NOT NULL,
            grievance_level REAL DEFAULT 0.0,
            fixation_level REAL DEFAULT 0.0,
            identification_level REAL DEFAULT 0.0,
            novel_aggression REAL DEFAULT 0.0,
            energy_burst REAL DEFAULT 0.0,
            leakage REAL DEFAULT 0.0,
            last_resort REAL DEFAULT 0.0,
            directly_communicated_threat REAL DEFAULT 0.0,
            pathway_score REAL DEFAULT 0.0,
            escalation_trend TEXT DEFAULT 'stable',
            evidence_summary TEXT,
            source_alert_ids TEXT DEFAULT '[]',
            analyst_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(subject_id, assessment_date),
            FOREIGN KEY (subject_id) REFERENCES threat_subjects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS sitreps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trigger_type TEXT NOT NULL,
            trigger_alert_id INTEGER,
            trigger_poi_id INTEGER,
            trigger_location_id INTEGER,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            situation_summary TEXT,
            threat_assessment TEXT,
            affected_protectees TEXT DEFAULT '[]',
            affected_locations TEXT DEFAULT '[]',
            recommended_actions TEXT DEFAULT '[]',
            escalation_tier TEXT,
            escalation_notify TEXT DEFAULT '[]',
            content_md TEXT,
            status TEXT DEFAULT 'draft',
            issued_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (trigger_alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
            FOREIGN KEY (trigger_poi_id) REFERENCES pois(id) ON DELETE SET NULL,
            FOREIGN KEY (trigger_location_id) REFERENCES protected_locations(id) ON DELETE SET NULL
        );
        """
    )

    _ensure_schema_migrations_table(conn)
    migration_name = "compact_poi_assessments_v1"
    if not _has_schema_migration(conn, migration_name):
        compacted_rows = _compact_legacy_poi_assessments(conn)
        if compacted_rows > 0:
            try:
                conn.execute(
                    "INSERT INTO retention_log (action, rows_affected) VALUES (?, ?)",
                    ("compact_poi_assessments", int(compacted_rows)),
                )
            except sqlite3.OperationalError:
                pass
        _mark_schema_migration(conn, migration_name)

    # Standardize on flat alert_entities storage; remove legacy normalized tables.
    for sql in (
        "DROP TABLE IF EXISTS alert_iocs",
        "DROP TABLE IF EXISTS iocs",
        "DROP TABLE IF EXISTS entities",
    ):
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass

    # Indexes for performance
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_duplicate_of ON alerts(duplicate_of)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_date ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_published_date ON alerts(published_at)",
        "CREATE INDEX IF NOT EXISTS idx_keyword_frequency_kw_date ON keyword_frequency(keyword_id, date)",
        "CREATE INDEX IF NOT EXISTS idx_alert_entities_alert ON alert_entities(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_entities_type_value ON alert_entities(entity_type, entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_poi_aliases_poi ON poi_aliases(poi_id)",
        "CREATE INDEX IF NOT EXISTS idx_poi_hits_poi ON poi_hits(poi_id)",
        "CREATE INDEX IF NOT EXISTS idx_poi_hits_alert ON poi_hits(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_locations_alert ON alert_locations(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_proximity_alert ON alert_proximity(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_start_dt ON events(start_dt)",
        "CREATE INDEX IF NOT EXISTS idx_poi_assessments_poi_window ON poi_assessments(poi_id, window_start, window_end)",
        "CREATE INDEX IF NOT EXISTS idx_threat_subjects_status ON threat_subjects(status)",
        "CREATE INDEX IF NOT EXISTS idx_tsa_subject_date ON threat_subject_assessments(subject_id, assessment_date)",
        "CREATE INDEX IF NOT EXISTS idx_sitreps_status ON sitreps(status)",
        "CREATE INDEX IF NOT EXISTS idx_sitreps_created ON sitreps(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_sitreps_trigger_poi ON sitreps(trigger_poi_id)",
    ]
    for sql in indexes:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass

    conn.execute("UPDATE keywords SET weight = 1.0 WHERE weight IS NULL")
    conn.execute("UPDATE sources SET credibility_score = 0.5 WHERE credibility_score IS NULL")
    conn.execute("UPDATE alerts SET risk_score = 0.0 WHERE risk_score IS NULL")
    conn.execute("UPDATE alerts SET ors_score = risk_score WHERE ors_score IS NULL OR ors_score = 0.0")
    conn.execute("UPDATE alerts SET tas_score = 0.0 WHERE tas_score IS NULL")
    conn.execute("UPDATE alerts SET published_at = created_at WHERE published_at IS NULL")
    conn.commit()
    conn.close()


def _normalize_keyword_category(raw_category):
    normalized = (raw_category or "general").strip().lower().replace(" ", "_")
    return KEYWORD_CATEGORY_ALIASES.get(normalized, normalized or "general")


def _default_keyword_weight(category):
    return KEYWORD_DEFAULT_WEIGHTS_BY_CATEGORY.get(category, 1.0)


def build_gdelt_rss_url(query, maxrecords=100, timespan="24h", sort="datedesc"):
    """Build a URL-encoded GDELT DOC API RSS feed URL."""
    query_text = str(query or "").strip()
    if not query_text:
        raise ValueError("query must not be empty")
    safe_maxrecords = max(1, min(250, int(maxrecords)))
    params = {
        "query": query_text,
        "mode": "artlist",
        "format": "rss",
        "maxrecords": safe_maxrecords,
        "timespan": str(timespan),
        "sort": str(sort),
    }
    return f"{GDELT_DOC_API_BASE_URL}?{urlencode(params, quote_via=quote_plus)}"


def load_watchlist_yaml(config_path=None):
    """
    Load watchlist config from YAML.

    Expected structure:
      sources:
        rss/reddit/pastebin/darkweb: [{name, url}]
      keywords:
        <category>: [term, ...] or [{term, weight}, ...]
    """
    watchlist_path = config_path or WATCHLIST_CONFIG_PATH
    if not os.path.exists(watchlist_path):
        return None

    try:
        with open(watchlist_path, "r", encoding="utf-8") as f:
            payload = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return None

    if not isinstance(payload, dict):
        return None

    parsed = {
        "path": watchlist_path,
        "sources": [],
        "keywords": [],
        "pois": [],
        "protected_locations": [],
        "events": [],
        "escalation_tiers": [],
    }

    source_block = payload.get("sources", {})
    if isinstance(source_block, dict):
        for source_type in ("rss", "reddit", "pastebin", "darkweb"):
            entries = source_block.get(source_type, [])
            if not isinstance(entries, list):
                continue
            default_credibility = SOURCE_DEFAULT_CREDIBILITY.get(source_type, 0.5)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip()
                raw_url = entry.get("url")
                gdelt_query = str(entry.get("gdelt_query", "")).strip()
                url = str(raw_url).strip() if raw_url else ""
                if not url and gdelt_query:
                    try:
                        url = build_gdelt_rss_url(gdelt_query)
                    except (TypeError, ValueError):
                        url = ""
                if not name or not url:
                    continue
                cred_raw = entry.get("credibility_score", entry.get("credibility"))
                try:
                    credibility = float(cred_raw) if cred_raw is not None else default_credibility
                except (TypeError, ValueError):
                    credibility = default_credibility
                credibility = max(0.0, min(1.0, credibility))
                parsed["sources"].append(
                    {
                        "name": name,
                        "url": url,
                        "source_type": source_type,
                        "credibility_score": credibility,
                    }
                )

    def _collect_keywords(keyword_block):
        collected = []
        if not isinstance(keyword_block, dict):
            return collected
        seen_terms = set()
        for raw_category, terms in keyword_block.items():
            if not isinstance(terms, list):
                continue
            category = _normalize_keyword_category(raw_category)
            default_weight = _default_keyword_weight(category)
            for term_item in terms:
                weight = default_weight
                if isinstance(term_item, dict):
                    term_text = str(term_item.get("term", "")).strip()
                    raw_weight = term_item.get("weight")
                    if raw_weight is not None:
                        try:
                            weight = float(raw_weight)
                        except (TypeError, ValueError):
                            weight = default_weight
                else:
                    term_text = str(term_item).strip()

                if not term_text:
                    continue
                dedupe_key = term_text.lower()
                if dedupe_key in seen_terms:
                    continue
                seen_terms.add(dedupe_key)
                weight = max(0.1, min(5.0, weight))
                collected.append(
                    {"term": term_text, "category": category, "weight": weight}
                )
        return collected

    keyword_items = _collect_keywords(payload.get("keywords", {}))
    cti_items = _collect_keywords(payload.get("cti_optional", {}))
    parsed["keywords"].extend(keyword_items)
    existing_terms = {item["term"].lower() for item in parsed["keywords"]}
    for item in cti_items:
        if item["term"].lower() in existing_terms:
            continue
        parsed["keywords"].append(item)
        existing_terms.add(item["term"].lower())

    pois = payload.get("pois", [])
    if isinstance(pois, list):
        for item in pois:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            aliases = item.get("aliases", [])
            if not isinstance(aliases, list):
                aliases = []
            parsed["pois"].append(
                {
                    "name": name,
                    "org": str(item.get("org", "")).strip() or None,
                    "role": str(item.get("role", "")).strip() or None,
                    "sensitivity": int(item.get("sensitivity", 3) or 3),
                    "aliases": [str(alias).strip() for alias in aliases if str(alias).strip()],
                }
            )

    protected_locations = payload.get("protected_locations", [])
    if isinstance(protected_locations, list):
        for item in protected_locations:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            parsed["protected_locations"].append(
                {
                    "name": name,
                    "type": str(item.get("type", "")).strip() or None,
                    "lat": item.get("lat"),
                    "lon": item.get("lon"),
                    "radius_miles": item.get("radius_miles", 5.0),
                    "notes": str(item.get("notes", "")).strip() or None,
                }
            )

    events = payload.get("events", [])
    if isinstance(events, list):
        for item in events:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            start_dt = str(item.get("start_dt", "")).strip()
            end_dt = str(item.get("end_dt", "")).strip()
            if not name or not start_dt or not end_dt:
                continue
            parsed["events"].append(
                {
                    "name": name,
                    "type": str(item.get("type", "")).strip() or None,
                    "start_dt": start_dt,
                    "end_dt": end_dt,
                    "city": str(item.get("city", "")).strip() or None,
                    "country": str(item.get("country", "")).strip() or None,
                    "venue": str(item.get("venue", "")).strip() or None,
                    "lat": item.get("lat"),
                    "lon": item.get("lon"),
                    "poi_name": str(item.get("poi_name", "")).strip() or None,
                    "notes": str(item.get("notes", "")).strip() or None,
                }
            )

    escalation_tiers = payload.get("escalation_tiers", [])
    if isinstance(escalation_tiers, list):
        for tier in escalation_tiers:
            if not isinstance(tier, dict):
                continue
            label = str(tier.get("label", "")).strip()
            if not label:
                continue
            try:
                threshold = float(tier.get("threshold", 0))
            except (TypeError, ValueError):
                threshold = 0.0
            notify = tier.get("notify", [])
            if not isinstance(notify, list):
                notify = []
            parsed["escalation_tiers"].append(
                {
                    "threshold": threshold,
                    "label": label,
                    "notify": [str(n).strip() for n in notify if str(n).strip()],
                    "action": str(tier.get("action", "")).strip() or None,
                    "response_window": str(tier.get("response_window", "")).strip() or None,
                }
            )
        # Sort tiers by threshold descending so highest priority comes first.
        parsed["escalation_tiers"].sort(key=lambda t: t["threshold"], reverse=True)

    return parsed


def seed_default_sources():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["sources"]:
        sources = [
            (
                source["name"],
                source["url"],
                source["source_type"],
                source["credibility_score"],
            )
            for source in watchlist["sources"]
        ]
        seed_origin = f"config ({watchlist['path']})"
    else:
        sources = [
            ("State Dept Travel Alerts/Warnings", "https://travel.state.gov/_res/rss/TAsTWs.xml", "rss", 0.9),
            ("CDC Travel Health Notices", "https://wwwnc.cdc.gov/travel/rss/notices.xml", "rss", 0.85),
            ("WHO Disease Outbreak News", "https://www.who.int/feeds/entity/csr/don/en/rss.xml", "rss", 0.85),
            (
                "GDELT PI/EP Watch",
                build_gdelt_rss_url(DEFAULT_GDELT_PI_EP_QUERY),
                "rss",
                0.6,
            ),
            ("r/OSINT", "https://www.reddit.com/r/OSINT/.rss", "reddit", 0.5),
            ("r/security", "https://www.reddit.com/r/security/.rss", "reddit", 0.45),
        ]
        seed_origin = "hardcoded defaults"

    for name, url, source_type, credibility in sources:
        existing = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE sources SET name = ?, source_type = ?, credibility_score = ? WHERE id = ?",
                (name, source_type, credibility, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO sources (name, url, source_type, credibility_score) VALUES (?, ?, ?, ?)",
                (name, url, source_type, credibility),
            )
    # Keep demo fixture sources from polluting normal scrape runs.
    conn.execute(
        """UPDATE sources
        SET source_type = 'demo', active = 0
        WHERE LOWER(name) LIKE 'demo %'
           OR url LIKE 'https://example.org/demo-%'"""
    )
    conn.commit()
    conn.close()
    print(f"Default sources seeded from {seed_origin}.")


def seed_default_keywords():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["keywords"]:
        keywords = [
            (keyword["term"], keyword["category"], keyword["weight"])
            for keyword in watchlist["keywords"]
        ]
        seed_origin = f"config ({watchlist['path']})"
    else:
        keywords = [
            ("death threat", "protective_intel", 5.0),
            ("swatting", "protective_intel", 4.2),
            ("doxxing", "protective_intel", 4.0),
            ("bomb threat", "protective_intel", 5.0),
            ("active shooter", "protective_intel", 5.0),
            ("threat to CEO", "protective_intel", 4.8),
            ("hostile surveillance", "protective_intel", 4.3),
            ("kidnapping", "protective_intel", 5.0),
            ("stalking", "protective_intel", 3.8),
            ("protest", "protest_disruption", 2.1),
            ("blockade", "protest_disruption", 2.6),
            ("curfew", "travel_risk", 3.2),
            ("unrest", "travel_risk", 3.4),
            ("airport disruption", "travel_risk", 2.8),
            ("travel advisory", "travel_risk", 3.8),
            ("civil unrest", "travel_risk", 3.4),
            ("evacuation", "travel_risk", 3.7),
            ("disgruntled", "insider_workplace", 3.3),
            ("restraining order", "insider_workplace", 4.1),
            ("insider threat", "insider_workplace", 3.4),
        ]
        seed_origin = "hardcoded defaults"

    for term, category, weight in keywords:
        existing = conn.execute("SELECT id FROM keywords WHERE term = ?", (term,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE keywords SET category = ?, weight = ? WHERE id = ?",
                (category, weight, existing["id"]),
            )
        else:
            try:
                conn.execute(
                    "INSERT INTO keywords (term, category, weight) VALUES (?, ?, ?)",
                    (term, category, weight),
                )
            except sqlite3.IntegrityError:
                pass
    conn.commit()
    conn.close()
    print(f"Default keywords seeded from {seed_origin}.")


def seed_default_pois():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["pois"]:
        pois = watchlist["pois"]
        seed_origin = f"config ({watchlist['path']})"
    else:
        pois = [
            {
                "name": "Tim Cook",
                "org": "Apple Inc.",
                "role": "Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Tim Cook", "Timothy D. Cook", "Timothy Cook"],
            },
            {
                "name": "Satya Nadella",
                "org": "Microsoft Corporation",
                "role": "Chairman & Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Satya Nadella", "Satya N. Nadella"],
            },
            {
                "name": "Sundar Pichai",
                "org": "Alphabet Inc.",
                "role": "Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Sundar Pichai", "Pichai Sundararajan"],
            },
            {
                "name": "Andy Jassy",
                "org": "Amazon.com Inc.",
                "role": "President & Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Andy Jassy", "Andrew R. Jassy", "Andrew Jassy"],
            },
            {
                "name": "Jensen Huang",
                "org": "NVIDIA Corporation",
                "role": "Founder & Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Jensen Huang", "Jen-Hsun Huang"],
            },
            {
                "name": "Mark Zuckerberg",
                "org": "Meta Platforms Inc.",
                "role": "Founder, Chairman & Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Mark Zuckerberg", "Mark E. Zuckerberg", "Zuckerberg"],
            },
            {
                "name": "Elon Musk",
                "org": "Tesla Inc.",
                "role": "Chief Executive Officer",
                "sensitivity": 5,
                "aliases": ["Elon Musk", "Elon R. Musk", "Musk"],
            },
        ]
        seed_origin = "hardcoded defaults"

    for poi in pois:
        existing = conn.execute("SELECT id FROM pois WHERE name = ?", (poi["name"],)).fetchone()
        if existing:
            poi_id = existing["id"]
            conn.execute(
                """UPDATE pois SET org = ?, role = ?, sensitivity = ?, active = 1
                WHERE id = ?""",
                (poi.get("org"), poi.get("role"), int(poi.get("sensitivity", 3)), poi_id),
            )
        else:
            conn.execute(
                "INSERT INTO pois (name, org, role, sensitivity, active) VALUES (?, ?, ?, ?, 1)",
                (poi["name"], poi.get("org"), poi.get("role"), int(poi.get("sensitivity", 3))),
            )
            poi_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        aliases = poi.get("aliases") or [poi["name"]]
        for alias in aliases:
            if not alias:
                continue
            conn.execute(
                """INSERT INTO poi_aliases (poi_id, alias, alias_type, active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(poi_id, alias) DO UPDATE SET active = 1""",
                (poi_id, alias, "name"),
            )
    conn.commit()
    conn.close()
    print(f"Default POIs seeded from {seed_origin}.")


def seed_default_protected_locations():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["protected_locations"]:
        locations = watchlist["protected_locations"]
        seed_origin = f"config ({watchlist['path']})"
    else:
        locations = [
            {
                "name": "Apple Park",
                "type": "hq",
                "lat": 37.3349,
                "lon": -122.0090,
                "radius_miles": 5,
                "notes": "Apple Inc. global headquarters, Cupertino CA",
            },
            {
                "name": "Microsoft Campus",
                "type": "hq",
                "lat": 47.6405,
                "lon": -122.1298,
                "radius_miles": 5,
                "notes": "Microsoft Corporation headquarters, Redmond WA",
            },
            {
                "name": "Googleplex",
                "type": "hq",
                "lat": 37.4220,
                "lon": -122.0841,
                "radius_miles": 5,
                "notes": "Alphabet/Google headquarters, Mountain View CA",
            },
            {
                "name": "Amazon HQ (Day 1)",
                "type": "hq",
                "lat": 47.6152,
                "lon": -122.3390,
                "radius_miles": 5,
                "notes": "Amazon.com headquarters, Seattle WA",
            },
            {
                "name": "NVIDIA HQ",
                "type": "hq",
                "lat": 37.3708,
                "lon": -121.9630,
                "radius_miles": 5,
                "notes": "NVIDIA Corporation headquarters, Santa Clara CA",
            },
            {
                "name": "Meta HQ (MPK)",
                "type": "hq",
                "lat": 37.4848,
                "lon": -122.1484,
                "radius_miles": 5,
                "notes": "Meta Platforms headquarters, Menlo Park CA",
            },
            {
                "name": "Tesla HQ (Gigafactory Texas)",
                "type": "hq",
                "lat": 30.2234,
                "lon": -97.6168,
                "radius_miles": 8,
                "notes": "Tesla Inc. headquarters & Gigafactory, Austin TX",
            },
        ]
        seed_origin = "hardcoded defaults"

    for location in locations:
        existing = conn.execute(
            "SELECT id FROM protected_locations WHERE name = ?",
            (location["name"],),
        ).fetchone()
        payload = (
            location.get("type"),
            location.get("lat"),
            location.get("lon"),
            float(location.get("radius_miles", 5.0) or 5.0),
            location.get("notes"),
            location["name"],
        )
        if existing:
            conn.execute(
                """UPDATE protected_locations
                SET type = ?, lat = ?, lon = ?, radius_miles = ?, notes = ?, active = 1
                WHERE name = ?""",
                payload,
            )
        else:
            conn.execute(
                """INSERT INTO protected_locations
                (name, type, lat, lon, radius_miles, notes, active)
                VALUES (?, ?, ?, ?, ?, ?, 1)""",
                (
                    location["name"],
                    location.get("type"),
                    location.get("lat"),
                    location.get("lon"),
                    float(location.get("radius_miles", 5.0) or 5.0),
                    location.get("notes"),
                ),
            )
    conn.commit()
    conn.close()
    print(f"Protected locations seeded from {seed_origin}.")


def seed_default_events():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["events"]:
        events = watchlist["events"]
        seed_origin = f"config ({watchlist['path']})"
    else:
        events = [
            {
                "name": "NVIDIA GTC 2026",
                "type": "corporate_event",
                "start_dt": "2026-03-17 09:00:00",
                "end_dt": "2026-03-20 17:00:00",
                "city": "San Jose",
                "country": "US",
                "venue": "San Jose Convention Center",
                "lat": 37.3302,
                "lon": -121.8889,
                "poi_name": "Jensen Huang",
                "notes": "GPU Technology Conference; Jensen keynote",
            },
            {
                "name": "Apple WWDC 2026",
                "type": "corporate_event",
                "start_dt": "2026-06-08 10:00:00",
                "end_dt": "2026-06-12 18:00:00",
                "city": "Cupertino",
                "country": "US",
                "venue": "Apple Park",
                "lat": 37.3349,
                "lon": -122.0090,
                "poi_name": "Tim Cook",
                "notes": "Annual developer conference; keynote high-profile",
            },
            {
                "name": "Tesla Annual Shareholder Meeting 2026",
                "type": "corporate_event",
                "start_dt": "2026-06-15 14:00:00",
                "end_dt": "2026-06-15 18:00:00",
                "city": "Austin",
                "country": "US",
                "venue": "Tesla HQ (Gigafactory Texas)",
                "lat": 30.2234,
                "lon": -97.6168,
                "poi_name": "Elon Musk",
                "notes": "Annual meeting; high public interest; protest risk",
            },
        ]
        seed_origin = "hardcoded defaults"

    for event in events:
        poi_id = None
        if event.get("poi_name"):
            row = conn.execute("SELECT id FROM pois WHERE name = ?", (event["poi_name"],)).fetchone()
            poi_id = row["id"] if row else None

        existing = conn.execute(
            "SELECT id FROM events WHERE name = ? AND start_dt = ?",
            (event["name"], event["start_dt"]),
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE events SET
                    type = ?, end_dt = ?, city = ?, country = ?, venue = ?, lat = ?, lon = ?, poi_id = ?, notes = ?
                   WHERE id = ?""",
                (
                    event.get("type"),
                    event["end_dt"],
                    event.get("city"),
                    event.get("country"),
                    event.get("venue"),
                    event.get("lat"),
                    event.get("lon"),
                    poi_id,
                    event.get("notes"),
                    existing["id"],
                ),
            )
        else:
            conn.execute(
                """INSERT INTO events
                (name, type, start_dt, end_dt, city, country, venue, lat, lon, poi_id, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["name"],
                    event.get("type"),
                    event["start_dt"],
                    event["end_dt"],
                    event.get("city"),
                    event.get("country"),
                    event.get("venue"),
                    event.get("lat"),
                    event.get("lon"),
                    poi_id,
                    event.get("notes"),
                ),
            )
    conn.commit()
    conn.close()
    print(f"Events seeded from {seed_origin}.")


def seed_threat_actors():
    conn = get_connection()
    # EP-relevant threat actor categories (physical security focus).
    # Threat subjects with behavioral assessments are the primary EP tracking
    # mechanism; this table provides reference context for known groups.
    actors = []
    for name, aliases, description in actors:
        existing = conn.execute("SELECT id FROM threat_actors WHERE name = ?", (name,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO threat_actors (name, aliases, description) VALUES (?, ?, ?)",
                (name, aliases, description),
            )
    conn.commit()
    conn.close()
    print("Threat actors seeded.")


def purge_raw_content(retention_days=None):
    conn = get_connection()
    try:
        days_raw = retention_days if retention_days is not None else os.getenv(
            "RAW_CONTENT_RETENTION_DAYS", "30"
        )
        days = max(1, int(days_raw))
    except (TypeError, ValueError):
        days = 30
    cutoff = f"-{days} days"
    result = conn.execute(
        """UPDATE alerts
        SET content = NULL
        WHERE content IS NOT NULL
          AND COALESCE(published_at, created_at) < datetime('now', ?)""",
        (cutoff,),
    )
    conn.execute(
        "INSERT INTO retention_log (action, rows_affected) VALUES (?, ?)",
        (f"purge_raw_content_{days}d", int(result.rowcount or 0)),
    )
    conn.commit()
    conn.close()
    print(f"Purged raw content older than {days} days ({result.rowcount or 0} rows).")


if __name__ == "__main__":
    init_db()
    migrate_schema()
    seed_default_sources()
    seed_default_keywords()
    seed_default_pois()
    seed_default_protected_locations()
    seed_default_events()
    seed_threat_actors()
    print("Setup complete.")
