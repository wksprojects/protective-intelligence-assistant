"""Protectee/POI matching for alert text."""

import os
import re
from difflib import SequenceMatcher


def _context_snippet(text, start, end, window=80):
    left = max(0, start - window)
    right = min(len(text), end + window)
    return " ".join(text[left:right].split())


def _find_exact_matches(text, alias):
    pattern = re.compile(r"\b" + re.escape(alias) + r"\b", flags=re.IGNORECASE)
    return [m for m in pattern.finditer(text)]


def _find_fuzzy_matches(text, alias, threshold=0.90):
    """Conservative fuzzy matching for multi-token aliases only."""
    alias_tokens = alias.split()
    if len(alias_tokens) < 2:
        return []

    token_spans = [
        (match.group(0), match.start(), match.end()) for match in re.finditer(r"\b[\w'.-]+\b", text)
    ]
    text_tokens = [token for token, _, _ in token_spans]
    if len(text_tokens) < len(alias_tokens):
        return []

    matches = []
    lowered_alias = alias.lower()
    for idx in range(0, len(text_tokens) - len(alias_tokens) + 1):
        candidate = " ".join(text_tokens[idx : idx + len(alias_tokens)])
        score = SequenceMatcher(None, lowered_alias, candidate.lower()).ratio()
        if score >= threshold:
            # Map the token window directly back to character offsets.
            start = token_spans[idx][1]
            end = token_spans[idx + len(alias_tokens) - 1][2]
            matches.append((start, end, score))
    return matches


def get_active_poi_aliases(conn):
    rows = conn.execute(
        """SELECT p.id AS poi_id, p.name AS poi_name, p.org, p.role,
                  COALESCE(p.sensitivity, 3) AS sensitivity,
                  a.alias, a.alias_type
           FROM pois p
           JOIN poi_aliases a ON a.poi_id = p.id
           WHERE p.active = 1 AND a.active = 1"""
    ).fetchall()
    return [dict(row) for row in rows]


def match_pois(text, aliases):
    safe_text = text or ""
    matches = []
    seen = set()
    allow_single_token = os.getenv("ENABLE_SINGLE_TOKEN_POI", "0").lower() in {"1", "true", "yes"}

    for alias_row in aliases:
        alias = (alias_row.get("alias") or "").strip()
        if not alias:
            continue
        token_count = len(alias.split())

        for exact in _find_exact_matches(safe_text, alias):
            score = 1.0 if token_count >= 2 else 0.35
            if token_count == 1 and not allow_single_token:
                continue
            key = (alias_row["poi_id"], alias.lower(), exact.start())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "poi_id": alias_row["poi_id"],
                    "poi_name": alias_row.get("poi_name"),
                    "match_type": "exact" if token_count >= 2 else "supporting_single_token",
                    "match_value": alias,
                    "match_score": round(score, 3),
                    "context": _context_snippet(safe_text, exact.start(), exact.end()),
                }
            )

        if token_count >= 2:
            for start, end, score in _find_fuzzy_matches(safe_text, alias, threshold=0.90):
                key = (alias_row["poi_id"], alias.lower(), start)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    {
                        "poi_id": alias_row["poi_id"],
                        "poi_name": alias_row.get("poi_name"),
                        "match_type": "fuzzy",
                        "match_value": alias,
                        "match_score": round(float(score), 3),
                        "context": _context_snippet(safe_text, start, end),
                    }
                )

    matches.sort(key=lambda x: x["match_score"], reverse=True)
    return matches


def store_poi_hits(conn, alert_id, hits):
    for hit in hits:
        conn.execute(
            """INSERT INTO poi_hits
            (poi_id, alert_id, match_type, match_value, match_score, context, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(poi_id, alert_id, match_value) DO UPDATE SET
                match_type = excluded.match_type,
                match_score = excluded.match_score,
                context = COALESCE(excluded.context, poi_hits.context)""",
            (
                hit["poi_id"],
                alert_id,
                hit["match_type"],
                hit["match_value"],
                float(hit["match_score"]),
                hit.get("context"),
            ),
        )


def process_alert_poi_hits(conn, alert_id, text):
    aliases = get_active_poi_aliases(conn)
    hits = match_pois(text, aliases)
    store_poi_hits(conn, alert_id, hits)
    return hits
