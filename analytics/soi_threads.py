"""Alert correlation threads for Subject-of-Interest timelines."""

from collections import defaultdict
from datetime import timedelta

from analytics.utils import parse_timestamp, utcnow
from database.init_db import get_connection

_SHARED_ENTITY_TYPES = {"actor_handle", "domain", "ipv4", "url"}


class _UnionFind:
    def __init__(self, items):
        self.parent = {item: item for item in items}
        self.rank = {item: 0 for item in items}

    def find(self, item):
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left, right):
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return
        rank_left = self.rank[root_left]
        rank_right = self.rank[root_right]
        if rank_left < rank_right:
            self.parent[root_left] = root_right
            return
        if rank_left > rank_right:
            self.parent[root_right] = root_left
            return
        self.parent[root_right] = root_left
        self.rank[root_left] += 1


def _within_hours(left_dt, right_dt, max_hours):
    if left_dt is None or right_dt is None:
        return False
    diff_seconds = abs((left_dt - right_dt).total_seconds())
    return diff_seconds <= float(max_hours) * 3600.0


def _connect_pairs(uf, alerts_by_id, grouped_alert_ids, max_hours):
    for alert_ids in grouped_alert_ids.values():
        ids = list(alert_ids)
        if len(ids) < 2:
            continue
        for idx in range(len(ids)):
            left_id = ids[idx]
            left_ts = alerts_by_id[left_id]["timestamp_dt"]
            for jdx in range(idx + 1, len(ids)):
                right_id = ids[jdx]
                right_ts = alerts_by_id[right_id]["timestamp_dt"]
                if _within_hours(left_ts, right_ts, max_hours):
                    uf.union(left_id, right_id)


def build_soi_threads(
    days=14,
    window_hours=72,
    min_cluster_size=2,
    limit=50,
    include_demo=False,
):
    safe_days = max(1, min(int(days), 90))
    safe_window_hours = max(1, min(int(window_hours), 720))
    safe_min_cluster = max(2, min(int(min_cluster_size), 20))
    safe_limit = max(1, min(int(limit), 200))
    cutoff = (utcnow() - timedelta(days=safe_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    demo_filter = ""
    if not include_demo:
        demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"

    try:
        alert_rows = conn.execute(
            f"""SELECT a.id, a.title, a.url, a.matched_term, a.severity,
                      COALESCE(a.ors_score, a.risk_score, 0) AS ors_score,
                      COALESCE(a.tas_score, 0) AS tas_score,
                      COALESCE(a.published_at, a.created_at) AS ts,
                      s.name AS source_name,
                      s.source_type
            FROM alerts a
            LEFT JOIN sources s ON s.id = a.source_id
            WHERE a.duplicate_of IS NULL
              AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime(?)
              {demo_filter}
            ORDER BY datetime(COALESCE(a.published_at, a.created_at)) DESC""",
            (cutoff,),
        ).fetchall()

        if len(alert_rows) < safe_min_cluster:
            return []

        alerts_by_id = {}
        for row in alert_rows:
            payload = dict(row)
            payload["timestamp_dt"] = parse_timestamp(payload.get("ts"))
            alerts_by_id[int(payload["id"])] = payload

        alert_ids = list(alerts_by_id.keys())
        placeholders = ",".join("?" for _ in alert_ids)
        uf = _UnionFind(alert_ids)

        poi_rows = conn.execute(
            f"""SELECT ph.alert_id, ph.poi_id, p.name AS poi_name
            FROM poi_hits ph
            JOIN pois p ON p.id = ph.poi_id
            WHERE ph.alert_id IN ({placeholders})""",
            alert_ids,
        ).fetchall()
        poi_groups = defaultdict(set)
        poi_name_by_id = {}
        for row in poi_rows:
            poi_id = int(row["poi_id"])
            alert_id = int(row["alert_id"])
            poi_groups[poi_id].add(alert_id)
            poi_name_by_id[poi_id] = row["poi_name"]
        _connect_pairs(uf, alerts_by_id, poi_groups, safe_window_hours)

        entity_rows = conn.execute(
            f"""SELECT alert_id, entity_type, entity_value
            FROM alert_entities
            WHERE alert_id IN ({placeholders})
              AND entity_type IN ({",".join("?" for _ in _SHARED_ENTITY_TYPES)})""",
            alert_ids + sorted(_SHARED_ENTITY_TYPES),
        ).fetchall()
        entity_groups = defaultdict(set)
        for row in entity_rows:
            key = (row["entity_type"], (row["entity_value"] or "").strip().lower())
            if not key[1]:
                continue
            entity_groups[key].add(int(row["alert_id"]))
        _connect_pairs(uf, alerts_by_id, entity_groups, safe_window_hours)

        keyword_groups = defaultdict(set)
        for alert_id, alert in alerts_by_id.items():
            term = (alert.get("matched_term") or "").strip().lower()
            if term:
                keyword_groups[term].add(alert_id)
        _connect_pairs(uf, alerts_by_id, keyword_groups, 24)

        clusters = defaultdict(list)
        for alert_id in alert_ids:
            clusters[uf.find(alert_id)].append(alert_id)

        entity_lookup = defaultdict(list)
        for row in entity_rows:
            entity_lookup[int(row["alert_id"])].append((row["entity_type"], row["entity_value"]))

        poi_lookup = defaultdict(set)
        for row in poi_rows:
            poi_lookup[int(row["alert_id"])].add(int(row["poi_id"]))

        threads = []
        for cluster_ids in clusters.values():
            if len(cluster_ids) < safe_min_cluster:
                continue
            timeline = []
            sources = set()
            matched_terms = set()
            actor_handles = set()
            shared_entities = set()
            poi_ids = set()
            max_ors = 0.0
            max_tas = 0.0

            for alert_id in cluster_ids:
                alert = alerts_by_id[alert_id]
                ts_text = alert.get("ts")
                timeline.append(
                    {
                        "alert_id": alert_id,
                        "timestamp": ts_text,
                        "source_name": alert.get("source_name"),
                        "source_type": alert.get("source_type"),
                        "title": alert.get("title"),
                        "url": alert.get("url"),
                        "matched_term": alert.get("matched_term"),
                        "severity": alert.get("severity"),
                        "ors_score": round(float(alert.get("ors_score") or 0.0), 3),
                        "tas_score": round(float(alert.get("tas_score") or 0.0), 3),
                    }
                )
                sources.add(alert.get("source_name") or "unknown")
                if alert.get("matched_term"):
                    matched_terms.add(alert["matched_term"])
                max_ors = max(max_ors, float(alert.get("ors_score") or 0.0))
                max_tas = max(max_tas, float(alert.get("tas_score") or 0.0))
                for poi_id in poi_lookup.get(alert_id, set()):
                    poi_ids.add(poi_id)
                for entity_type, entity_value in entity_lookup.get(alert_id, []):
                    value = (entity_value or "").strip()
                    if not value:
                        continue
                    if entity_type == "actor_handle":
                        actor_handles.add(value)
                    else:
                        shared_entities.add(f"{entity_type}:{value}")

            timeline.sort(key=lambda item: parse_timestamp(item.get("timestamp")) or utcnow())
            if len(sources) < 2 and not actor_handles and not poi_ids:
                continue

            start_ts = timeline[0]["timestamp"]
            end_ts = timeline[-1]["timestamp"]
            poi_names = [poi_name_by_id.get(pid) for pid in sorted(poi_ids) if poi_name_by_id.get(pid)]

            label = None
            if actor_handles:
                label = f"Actor {sorted(actor_handles)[0]}"
            elif poi_names:
                label = f"POI {poi_names[0]}"
            elif matched_terms:
                label = f"Term {sorted(matched_terms)[0]}"
            else:
                label = "SOI Thread"

            threads.append(
                {
                    "thread_id": f"soi-{cluster_ids[0]}-{len(cluster_ids)}",
                    "label": label,
                    "alerts_count": len(cluster_ids),
                    "sources_count": len(sources),
                    "sources": sorted(sources),
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                    "max_ors_score": round(max_ors, 3),
                    "max_tas_score": round(max_tas, 3),
                    "poi_ids": sorted(poi_ids),
                    "poi_names": poi_names,
                    "actor_handles": sorted(actor_handles),
                    "shared_entities": sorted(shared_entities)[:20],
                    "matched_terms": sorted(matched_terms),
                    "timeline": timeline,
                }
            )

        threads.sort(
            key=lambda t: (
                float(t.get("max_ors_score") or 0.0),
                float(t.get("max_tas_score") or 0.0),
                parse_timestamp(t.get("end_ts")) or utcnow(),
            ),
            reverse=True,
        )
        return threads[:safe_limit]
    finally:
        conn.close()
