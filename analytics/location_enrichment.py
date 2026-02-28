"""Alert location extraction, optional geocoding, and proximity mapping."""

import os
import re
import time
from math import asin, cos, radians, sin, sqrt

import requests

from analytics.utils import utcnow

_SPACY_ATTEMPTED = False
_SPACY_NLP = None
_LAST_GEOCODE_AT = 0.0


def _load_spacy_model():
    global _SPACY_ATTEMPTED, _SPACY_NLP
    if _SPACY_ATTEMPTED:
        return _SPACY_NLP
    _SPACY_ATTEMPTED = True
    try:
        import spacy  # pylint: disable=import-outside-toplevel

        _SPACY_NLP = spacy.load("en_core_web_sm")
    except Exception:
        _SPACY_NLP = None
    return _SPACY_NLP


def _normalize_location(text):
    return " ".join((text or "").strip().split()).strip(".,;:")


def extract_location_mentions(text):
    safe_text = text or ""
    results = []
    seen = set()

    patterns = [
        re.compile(r"\bin\s+([A-Z][A-Za-z\s]+,\s*[A-Z]{2})\b"),
        re.compile(r"\bin\s+([A-Z][A-Za-z\s]+,\s*[A-Z][A-Za-z]+)\b"),
        re.compile(r"\bnear\s+([A-Z][A-Za-z\s]+)\b"),
    ]

    for pattern in patterns:
        for match in pattern.finditer(safe_text):
            loc = _normalize_location(match.group(1))
            if not loc:
                continue
            key = loc.lower()
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "location_text": loc,
                    "resolver": "regex",
                    "confidence": 0.55,
                }
            )

    nlp = _load_spacy_model()
    if nlp:
        doc = nlp(safe_text[:20000])
        for ent in doc.ents:
            if ent.label_ not in {"GPE", "LOC"}:
                continue
            loc = _normalize_location(ent.text)
            if not loc:
                continue
            key = loc.lower()
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "location_text": loc,
                    "resolver": "spacy",
                    "confidence": 0.8,
                }
            )

    return results


def _rate_limit_geocoder(min_interval_seconds=1.0):
    global _LAST_GEOCODE_AT
    elapsed = time.time() - _LAST_GEOCODE_AT
    if elapsed < min_interval_seconds:
        time.sleep(min_interval_seconds - elapsed)
    _LAST_GEOCODE_AT = time.time()


def geocode_query(conn, query, provider="nominatim"):
    """Geocode a location string with cache-first lookup."""
    normalized = _normalize_location(query)
    if not normalized:
        return None

    cached = conn.execute(
        "SELECT lat, lon FROM geocode_cache WHERE query = ?",
        (normalized.lower(),),
    ).fetchone()
    if cached:
        return float(cached["lat"]), float(cached["lon"])

    enabled = os.getenv("ENABLE_GEOCODING", "0").lower() in {"1", "true", "yes"}
    if not enabled:
        return None

    try:
        _rate_limit_geocoder(min_interval_seconds=1.0)
        response = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": normalized, "format": "json", "limit": 1},
            headers={
                "User-Agent": os.getenv(
                    "GEOCODER_USER_AGENT", "protective-intel-assistant/5.0 (contact: local-dev)"
                )
            },
            timeout=8,
        )
        response.raise_for_status()
        payload = response.json() or []
        if not payload:
            return None
        lat = float(payload[0]["lat"])
        lon = float(payload[0]["lon"])
        conn.execute(
            """INSERT INTO geocode_cache (query, lat, lon, provider, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(query) DO UPDATE SET
                lat = excluded.lat,
                lon = excluded.lon,
                provider = excluded.provider,
                updated_at = excluded.updated_at""",
            (normalized.lower(), lat, lon, provider, utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return lat, lon
    except Exception:
        return None


def _haversine_miles(lat1, lon1, lat2, lon2):
    r = 3958.756
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return r * c


def upsert_alert_locations(conn, alert_id, location_mentions, geocode_enabled=False):
    for mention in location_mentions:
        lat = lon = None
        if geocode_enabled:
            coords = geocode_query(conn, mention["location_text"])
            if coords:
                lat, lon = coords

        conn.execute(
            """INSERT INTO alert_locations
            (alert_id, location_text, lat, lon, resolver, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                alert_id,
                mention["location_text"],
                lat,
                lon,
                mention.get("resolver"),
                mention.get("confidence"),
            ),
        )


def update_alert_proximity(conn, alert_id):
    locs = conn.execute(
        """SELECT lat, lon FROM alert_locations
        WHERE alert_id = ? AND lat IS NOT NULL AND lon IS NOT NULL""",
        (alert_id,),
    ).fetchall()
    protected = conn.execute(
        """SELECT id, lat, lon, radius_miles FROM protected_locations
        WHERE active = 1 AND lat IS NOT NULL AND lon IS NOT NULL"""
    ).fetchall()
    if not locs or not protected:
        return

    for target in protected:
        min_distance = None
        for loc in locs:
            distance = _haversine_miles(
                float(loc["lat"]),
                float(loc["lon"]),
                float(target["lat"]),
                float(target["lon"]),
            )
            if min_distance is None or distance < min_distance:
                min_distance = distance
        if min_distance is None:
            continue
        within = 1 if min_distance <= float(target["radius_miles"] or 0.0) else 0
        conn.execute(
            """INSERT INTO alert_proximity
            (alert_id, protected_location_id, distance_miles, within_radius, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(alert_id, protected_location_id) DO UPDATE SET
                distance_miles = excluded.distance_miles,
                within_radius = excluded.within_radius,
                created_at = excluded.created_at""",
            (alert_id, target["id"], round(min_distance, 3), within),
        )


def process_alert_locations(conn, alert_id, text, geocode_enabled=False):
    mentions = extract_location_mentions(text)
    if not mentions:
        return []
    upsert_alert_locations(conn, alert_id, mentions, geocode_enabled=geocode_enabled)
    update_alert_proximity(conn, alert_id)
    return mentions
