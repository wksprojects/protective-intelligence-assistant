"""
Entity + IOC extraction for alert text.

spaCy NER is optional; regex IOC extraction always runs.
All extracted artifacts are persisted to alert_entities.
"""

import re

from analytics.entity_extraction import store_alert_entities

_SPACY_ATTEMPTED = False
_SPACY_NLP = None

ENTITY_LABELS = {"ORG", "PERSON", "GPE", "LOC"}

IOC_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,24}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>'\")]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def _context_snippet(text, start, end, window=60):
    left = max(0, start - window)
    right = min(len(text), end + window)
    return " ".join(text[left:right].split())


def _load_spacy_model():
    global _SPACY_ATTEMPTED, _SPACY_NLP
    if _SPACY_ATTEMPTED:
        return _SPACY_NLP

    _SPACY_ATTEMPTED = True
    try:
        import spacy  # pylint: disable=import-outside-toplevel

        _SPACY_NLP = spacy.load("en_core_web_sm")
    except (ImportError, OSError):
        _SPACY_NLP = None
    return _SPACY_NLP


def _normalize_ioc(ioc_type, value):
    normalized = value.strip().strip(".,);")
    if ioc_type in {"cve"}:
        return normalized.upper()
    if ioc_type in {"domain", "email", "md5", "sha1", "sha256"}:
        return normalized.lower()
    return normalized


def _extract_iocs(text):
    findings = []
    seen = set()

    spans_to_skip = []
    for pattern in (IOC_PATTERNS["url"], IOC_PATTERNS["email"]):
        for match in pattern.finditer(text):
            spans_to_skip.append((match.start(), match.end()))

    def _overlaps_skip(start, end):
        return any(start < s_end and end > s_start for s_start, s_end in spans_to_skip)

    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            if ioc_type == "domain" and _overlaps_skip(match.start(), match.end()):
                continue
            normalized = _normalize_ioc(ioc_type, match.group(0))
            key = (ioc_type, normalized)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": ioc_type,
                    "value": normalized,
                    "context": _context_snippet(text, match.start(), match.end()),
                }
            )
    return findings


def extract(text):
    """
    Extract entities and IOCs from unstructured text.

    Returns:
        {
            "entities": [{type, value, confidence, context}],
            "iocs": [{type, value, context}],
            "meta": {"extractor_used": "..."}
        }
    """
    safe_text = text or ""
    entities = []
    entity_seen = set()

    nlp = _load_spacy_model()
    extractor_used = "regex"

    if nlp:
        extractor_used = "spacy+regex"
        doc = nlp(safe_text[:20000])
        for ent in doc.ents:
            if ent.label_ not in ENTITY_LABELS:
                continue
            value = ent.text.strip()
            if not value:
                continue
            key = (ent.label_, value.lower())
            if key in entity_seen:
                continue
            entity_seen.add(key)
            entities.append(
                {
                    "type": ent.label_,
                    "value": value,
                    "confidence": 1.0,
                    "context": _context_snippet(safe_text, ent.start_char, ent.end_char),
                }
            )

    iocs = _extract_iocs(safe_text)

    return {
        "entities": entities,
        "iocs": iocs,
        "meta": {"extractor_used": extractor_used},
    }


def extract_and_store_alert_artifacts(conn, alert_id, text):
    """Extract entities/IOCs and persist flat artifacts for one alert."""
    extracted = extract(text)

    artifacts = [
        {"entity_type": item["type"], "entity_value": item["value"]}
        for item in extracted["entities"] + extracted["iocs"]
    ]
    store_alert_entities(conn, alert_id, artifacts)
    return extracted
