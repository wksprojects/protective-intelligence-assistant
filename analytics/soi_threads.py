"""Alert correlation threads for Subject-of-Interest timelines."""

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

from analytics.utils import parse_timestamp, utcnow
from database.init_db import get_connection

_SHARED_ENTITY_TYPES = {"actor_handle", "domain", "ipv4", "url", "user_id", "device_id", "vendor_id"}
_MAX_PAIR_CHECKS_PER_GROUP = 25000
_MIN_PAIR_LINK_SCORE = 0.35

_REASON_WEIGHTS = {
    "shared_actor_handle": 0.55,
    "shared_poi": 0.5,
    "shared_entity": 0.45,
    "shared_user_id": 0.5,
    "shared_device_id": 0.48,
    "shared_vendor_id": 0.48,
    "matched_term_temporal": 0.2,
    "shared_source_fingerprint": 0.15,
    "cross_source": 0.1,
    "tight_temporal": 0.1,
    "linguistic_overlap_high": 0.1,
    "linguistic_overlap_medium": 0.05,
}

_ENTITY_REASON_CODE = {
    "domain": "shared_entity",
    "ipv4": "shared_entity",
    "url": "shared_entity",
    "user_id": "shared_user_id",
    "device_id": "shared_device_id",
    "vendor_id": "shared_vendor_id",
}


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


def _normalize_tokens(value):
    if not value:
        return set()
    raw = str(value).lower()
    tokens = []
    token = []
    for ch in raw:
        if ch.isalnum() or ch in {"@", "_", "-"}:
            token.append(ch)
        else:
            if token:
                joined = "".join(token)
                if len(joined) >= 3:
                    tokens.append(joined)
                token = []
    if token:
        joined = "".join(token)
        if len(joined) >= 3:
            tokens.append(joined)
    return set(tokens)


def _source_fingerprint(source_type, url):
    parsed = urlparse(str(url or "").strip())
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    stype = (source_type or "unknown").strip().lower() or "unknown"
    return f"{stype}:{host or 'unknown'}"


def _pair_key(left_id, right_id):
    return (left_id, right_id) if left_id < right_id else (right_id, left_id)


def _record_pair(pair_scores, pair_reasons, left_id, right_id, score_delta, reasons):
    if score_delta <= 0:
        return
    key = _pair_key(left_id, right_id)
    pair_scores[key] = round(min(1.0, float(pair_scores.get(key, 0.0)) + float(score_delta)), 6)
    bucket = pair_reasons[key]
    for reason in reasons:
        if reason:
            bucket.add(str(reason))


def _jaccard(left_tokens, right_tokens):
    if not left_tokens or not right_tokens:
        return 0.0
    denom = len(left_tokens | right_tokens)
    if denom <= 0:
        return 0.0
    return len(left_tokens & right_tokens) / denom


def _connect_pairs(
    uf,
    alerts_by_id,
    grouped_alert_ids,
    max_hours,
    reason_code,
    reason_weight,
    pair_scores,
    pair_reasons,
    min_link_score=_MIN_PAIR_LINK_SCORE,
    max_pair_checks=_MAX_PAIR_CHECKS_PER_GROUP,
):
    max_seconds = float(max_hours) * 3600.0
    safe_max_pair_checks = max(1, int(max_pair_checks))
    link_threshold = max(0.0, float(min_link_score))

    for alert_ids in grouped_alert_ids.values():
        ids = [alert_id for alert_id in set(alert_ids) if alert_id in alerts_by_id]
        if len(ids) < 2:
            continue

        ids.sort(key=lambda aid: alerts_by_id[aid].get("timestamp_dt") or datetime.max)
        pair_checks = 0

        for idx in range(len(ids)):
            left_id = ids[idx]
            left = alerts_by_id[left_id]
            left_ts = left.get("timestamp_dt")
            if left_ts is None:
                continue

            for jdx in range(idx + 1, len(ids)):
                right_id = ids[jdx]
                right = alerts_by_id[right_id]
                right_ts = right.get("timestamp_dt")
                if right_ts is None:
                    continue

                delta_seconds = (right_ts - left_ts).total_seconds()
                if delta_seconds > max_seconds:
                    break

                pair_checks += 1
                if pair_checks > safe_max_pair_checks:
                    break

                score_delta = float(reason_weight)
                reasons = {reason_code}

                if left.get("source_type") and right.get("source_type"):
                    if left["source_type"] != right["source_type"]:
                        score_delta += _REASON_WEIGHTS["cross_source"]
                        reasons.add("cross_source")

                if abs(delta_seconds) <= 12 * 3600.0:
                    score_delta += _REASON_WEIGHTS["tight_temporal"]
                    reasons.add("tight_temporal")

                similarity = _jaccard(left.get("token_set") or set(), right.get("token_set") or set())
                if similarity >= 0.25:
                    score_delta += _REASON_WEIGHTS["linguistic_overlap_high"]
                    reasons.add("linguistic_overlap_high")
                elif similarity >= 0.15:
                    score_delta += _REASON_WEIGHTS["linguistic_overlap_medium"]
                    reasons.add("linguistic_overlap_medium")

                _record_pair(
                    pair_scores=pair_scores,
                    pair_reasons=pair_reasons,
                    left_id=left_id,
                    right_id=right_id,
                    score_delta=score_delta,
                    reasons=reasons,
                )

                if pair_scores.get(_pair_key(left_id, right_id), 0.0) >= link_threshold:
                    uf.union(left_id, right_id)

            if pair_checks > safe_max_pair_checks:
                break


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
            alert_id = int(payload["id"])
            payload["timestamp_dt"] = parse_timestamp(payload.get("ts"))
            payload["token_set"] = _normalize_tokens(
                f"{payload.get('title', '')} {payload.get('matched_term', '')}"
            )
            payload["source_fingerprint"] = _source_fingerprint(
                payload.get("source_type"), payload.get("url")
            )
            alerts_by_id[alert_id] = payload

        alert_ids = list(alerts_by_id.keys())
        placeholders = ",".join("?" for _ in alert_ids)
        uf = _UnionFind(alert_ids)
        pair_scores = defaultdict(float)
        pair_reasons = defaultdict(set)

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
        _connect_pairs(
            uf,
            alerts_by_id,
            poi_groups,
            safe_window_hours,
            "shared_poi",
            _REASON_WEIGHTS["shared_poi"],
            pair_scores,
            pair_reasons,
        )

        entity_rows = conn.execute(
            f"""SELECT alert_id, entity_type, entity_value
            FROM alert_entities
            WHERE alert_id IN ({placeholders})
              AND entity_type IN ({",".join("?" for _ in _SHARED_ENTITY_TYPES)})""",
            alert_ids + sorted(_SHARED_ENTITY_TYPES),
        ).fetchall()

        entity_groups_by_reason = defaultdict(lambda: defaultdict(set))
        actor_groups = defaultdict(set)
        for row in entity_rows:
            entity_type = row["entity_type"]
            value = (row["entity_value"] or "").strip().lower()
            if not value:
                continue
            alert_id = int(row["alert_id"])
            if entity_type == "actor_handle":
                actor_groups[value].add(alert_id)
            else:
                reason_code = _ENTITY_REASON_CODE.get(entity_type, "shared_entity")
                entity_groups_by_reason[reason_code][(entity_type, value)].add(alert_id)

        _connect_pairs(
            uf,
            alerts_by_id,
            actor_groups,
            safe_window_hours,
            "shared_actor_handle",
            _REASON_WEIGHTS["shared_actor_handle"],
            pair_scores,
            pair_reasons,
        )
        for reason_code, grouped_values in entity_groups_by_reason.items():
            _connect_pairs(
                uf,
                alerts_by_id,
                grouped_values,
                safe_window_hours,
                reason_code,
                _REASON_WEIGHTS.get(reason_code, _REASON_WEIGHTS["shared_entity"]),
                pair_scores,
                pair_reasons,
            )

        keyword_groups = defaultdict(set)
        source_fp_groups = defaultdict(set)
        for alert_id, alert in alerts_by_id.items():
            term = (alert.get("matched_term") or "").strip().lower()
            if term:
                keyword_groups[term].add(alert_id)
                source_fp_groups[(alert.get("source_fingerprint"), term)].add(alert_id)

        _connect_pairs(
            uf,
            alerts_by_id,
            keyword_groups,
            24,
            "matched_term_temporal",
            _REASON_WEIGHTS["matched_term_temporal"],
            pair_scores,
            pair_reasons,
        )
        _connect_pairs(
            uf,
            alerts_by_id,
            source_fp_groups,
            12,
            "shared_source_fingerprint",
            _REASON_WEIGHTS["shared_source_fingerprint"],
            pair_scores,
            pair_reasons,
        )

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

            cluster_set = set(cluster_ids)
            timeline = []
            sources = set()
            source_types = set()
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
                source_types.add(alert.get("source_type") or "unknown")
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

            cluster_pair_evidence = []
            for (left_id, right_id), score in pair_scores.items():
                if left_id in cluster_set and right_id in cluster_set:
                    reasons = sorted(pair_reasons.get((left_id, right_id), set()))
                    cluster_pair_evidence.append(
                        {
                            "left_alert_id": left_id,
                            "right_alert_id": right_id,
                            "score": round(float(score), 3),
                            "reason_codes": reasons,
                        }
                    )

            cluster_pair_evidence.sort(key=lambda item: item["score"], reverse=True)
            reason_codes = sorted(
                {
                    reason
                    for edge in cluster_pair_evidence
                    for reason in edge.get("reason_codes", [])
                    if reason
                }
            )

            if cluster_pair_evidence:
                avg_pair_score = sum(item["score"] for item in cluster_pair_evidence) / len(
                    cluster_pair_evidence
                )
                max_pair_score = cluster_pair_evidence[0]["score"]
                thread_confidence = round(min(1.0, 0.6 * max_pair_score + 0.4 * avg_pair_score), 3)
            else:
                thread_confidence = 0.0

            start_ts = timeline[0]["timestamp"]
            end_ts = timeline[-1]["timestamp"]
            poi_names = [poi_name_by_id.get(pid) for pid in sorted(poi_ids) if poi_name_by_id.get(pid)]

            if actor_handles and "shared_actor_handle" in reason_codes:
                label = f"Actor {sorted(actor_handles)[0]}"
            elif poi_names:
                label = f"POI {poi_names[0]}"
            elif matched_terms:
                label = f"Term {sorted(matched_terms)[0]}"
            else:
                label = "SOI Thread"

            threads.append(
                {
                    "thread_id": "soi-" + hashlib.sha256(
                        ",".join(str(aid) for aid in sorted(cluster_ids)).encode()
                    ).hexdigest()[:12],
                    "label": label,
                    "alerts_count": len(cluster_ids),
                    "sources_count": len(sources),
                    "source_types": sorted(source_types),
                    "sources": sorted(sources),
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                    "max_ors_score": round(max_ors, 3),
                    "max_tas_score": round(max_tas, 3),
                    "thread_confidence": thread_confidence,
                    "reason_codes": reason_codes,
                    "pair_evidence": cluster_pair_evidence[:20],
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
                float(t.get("thread_confidence") or 0.0),
                float(t.get("max_ors_score") or 0.0),
                float(t.get("max_tas_score") or 0.0),
                parse_timestamp(t.get("end_ts")) or utcnow(),
            ),
            reverse=True,
        )
        return threads[:safe_limit]
    finally:
        conn.close()
