from collections import defaultdict
from datetime import timedelta

from analytics.utils import utcnow
from database.init_db import get_connection

IOC_TYPES = {"ipv4", "domain", "url", "cve", "md5", "sha1", "sha256"}


def build_graph(days=7, min_score=70.0, limit_alerts=500, include_demo=False):
    """
    Build a compact link-analysis graph for high-risk recent alerts.

    Uses a single bulk query for entities instead of per-alert lookups
    to avoid the N+1 query pattern.
    """
    safe_days = max(1, min(int(days), 30))
    safe_limit = max(1, min(int(limit_alerts), 2000))
    cutoff = (utcnow() - timedelta(days=safe_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    demo_filter = ""
    if not include_demo:
        demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"
    alerts = conn.execute(
        f"""SELECT a.id, a.keyword_id, k.term AS keyword_term,
                  a.source_id, s.name AS source_name, a.risk_score
        FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        JOIN sources s ON a.source_id = s.id
        WHERE a.duplicate_of IS NULL
          AND COALESCE(a.published_at, a.created_at) >= ?
          AND a.risk_score >= ?
          {demo_filter}
        ORDER BY a.risk_score DESC
        LIMIT ?""",
        (cutoff, float(min_score), safe_limit),
    ).fetchall()

    # Bulk-fetch all entities for the selected alerts in a single query
    # instead of one query per alert (fixes N+1 performance issue).
    alert_ids = [alert["id"] for alert in alerts]
    entities_by_alert = defaultdict(list)
    if alert_ids:
        # SQLite parameter limit is ~999; chunk if needed
        chunk_size = 900
        for i in range(0, len(alert_ids), chunk_size):
            chunk = alert_ids[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"""SELECT alert_id, entity_type, entity_value
                FROM alert_entities
                WHERE alert_id IN ({placeholders})""",
                chunk,
            ).fetchall()
            for row in rows:
                entities_by_alert[row["alert_id"]].append(row)

    node_weights = defaultdict(float)
    node_meta = {}
    edge_weights = defaultdict(float)

    def add_node(node_id, label, node_type, weight):
        node_weights[node_id] += weight
        node_meta[node_id] = {"id": node_id, "label": label, "type": node_type}

    def add_edge(source, target, kind, weight):
        edge_weights[(source, target, kind)] += weight

    for alert in alerts:
        alert_weight = float(alert["risk_score"] or 0.0)
        source_node = f"source:{alert['source_id']}"
        keyword_node = f"keyword:{alert['keyword_id']}"
        add_node(source_node, alert["source_name"], "source", alert_weight)
        add_node(keyword_node, alert["keyword_term"], "keyword", alert_weight)
        add_edge(source_node, keyword_node, "source_keyword", alert_weight)

        for entity in entities_by_alert.get(alert["id"], []):
            entity_type = entity["entity_type"]
            entity_value = entity["entity_value"]
            if entity_type in IOC_TYPES:
                ioc_node = f"ioc:{entity_type}:{entity_value}"
                add_node(ioc_node, entity_value, f"ioc:{entity_type}", alert_weight)
                add_edge(keyword_node, ioc_node, "keyword_ioc", alert_weight)
            else:
                entity_node = f"entity:{entity_type}:{entity_value}"
                add_node(entity_node, entity_value, f"entity:{entity_type}", alert_weight)
                add_edge(keyword_node, entity_node, "keyword_entity", alert_weight)

    conn.close()

    nodes = []
    for node_id, meta in node_meta.items():
        nodes.append(
            {
                "id": node_id,
                "label": meta["label"],
                "type": meta["type"],
                "weight": round(node_weights[node_id], 3),
            }
        )
    nodes.sort(key=lambda x: x["weight"], reverse=True)

    edges = []
    for (source, target, kind), weight in edge_weights.items():
        edges.append(
            {
                "source": source,
                "target": target,
                "kind": kind,
                "weight": round(weight, 3),
            }
        )
    edges.sort(key=lambda x: x["weight"], reverse=True)

    return {"nodes": nodes, "edges": edges}
