CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    source_type TEXT NOT NULL,
    credibility_score REAL DEFAULT 0.5,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    bayesian_alpha REAL DEFAULT 2.0,
    bayesian_beta REAL DEFAULT 2.0,
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT NOT NULL UNIQUE,
    category TEXT DEFAULT 'general',
    weight REAL DEFAULT 1.0,
    weight_sigma REAL,
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    url TEXT,
    source_id INTEGER,
    keyword_id INTEGER,
    matched_term TEXT,
    content_hash TEXT,
    duplicate_of INTEGER,
    published_at TIMESTAMP,
    risk_score REAL DEFAULT 0.0,
    ors_score REAL DEFAULT 0.0,
    tas_score REAL DEFAULT 0.0,
    severity TEXT DEFAULT 'low',
    reviewed INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_id) REFERENCES sources(id),
    FOREIGN KEY (keyword_id) REFERENCES keywords(id)
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    aliases TEXT,
    description TEXT,
    alert_count INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    keyword_weight REAL NOT NULL,
    source_credibility REAL NOT NULL,
    frequency_factor REAL DEFAULT 1.0,
    z_score REAL DEFAULT 0.0,
    recency_factor REAL DEFAULT 1.0,
    category_factor REAL DEFAULT 0.0,
    proximity_factor REAL DEFAULT 0.0,
    event_factor REAL DEFAULT 0.0,
    poi_factor REAL DEFAULT 0.0,
    final_score REAL NOT NULL,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS keyword_frequency (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    UNIQUE(keyword_id, date),
    FOREIGN KEY (keyword_id) REFERENCES keywords(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intelligence_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_date TEXT NOT NULL UNIQUE,
    executive_summary TEXT NOT NULL,
    top_risks TEXT,
    emerging_themes TEXT,
    active_threat_actors TEXT,
    escalation_recommendations TEXT,
    top_entities TEXT,
    new_cves TEXT,
    total_alerts INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evaluation_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    period TEXT NOT NULL,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    total_reviewed INTEGER DEFAULT 0,
    precision REAL DEFAULT 0.0,
    recall REAL DEFAULT 0.0,
    f1_score REAL DEFAULT 0.0,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_id) REFERENCES sources(id)
);

CREATE TABLE IF NOT EXISTS scrape_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    scraper_type TEXT,
    total_sources INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0.0,
    alerts_per_second REAL DEFAULT 0.0,
    status TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS alert_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(alert_id, entity_type, entity_value),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alert_score_intervals (
    alert_id INTEGER PRIMARY KEY,
    n INTEGER NOT NULL,
    p05 REAL NOT NULL,
    p50 REAL NOT NULL,
    p95 REAL NOT NULL,
    mean REAL NOT NULL,
    std REAL NOT NULL,
    computed_at TEXT NOT NULL,
    method TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

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
