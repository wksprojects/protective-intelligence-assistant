"""Lightweight governance helpers (redaction + retention controls)."""

import os
import re


def redact_person_entities_enabled():
    return os.getenv("REDACT_PERSON_ENTITIES", "1").lower() in {"1", "true", "yes"}


def get_redaction_terms(conn):
    rows = conn.execute(
        """SELECT p.name AS term FROM pois p WHERE p.active = 1
           UNION
           SELECT a.alias AS term
           FROM poi_aliases a
           JOIN pois p ON p.id = a.poi_id
           WHERE a.active = 1 AND p.active = 1"""
    ).fetchall()
    terms = [row["term"] for row in rows if row["term"]]
    terms.sort(key=len, reverse=True)
    return terms


def redact_text(conn, text, redaction_terms=None):
    if not redact_person_entities_enabled():
        return text
    value = text or ""
    terms = redaction_terms if redaction_terms is not None else get_redaction_terms(conn)
    for term in terms:
        value = re.sub(
            r"\b" + re.escape(term) + r"\b", "[REDACTED_PERSON]", value, flags=re.IGNORECASE
        )
    return value
