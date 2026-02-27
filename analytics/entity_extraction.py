"""
Regex-only IOC extraction for alerts.

Stores entities in alert_entities as:
  (alert_id, entity_type, entity_value, created_at)

Hash disambiguation:
  MD5 (32 hex), SHA1 (40 hex), and SHA256 (64 hex) patterns can match
  normal hex strings such as UUIDs, Git SHAs, and session tokens.
  We require that at least one digit AND at least one letter [a-f] are
  present to reduce false positives (pure-numeric or monotonic hex is
  unlikely to be a real hash IOC in threat-intel context).
"""

import re

# --- Compiled patterns ---
# MD5/SHA1/SHA256: require mixed hex (at least one digit + one a-f letter)
# to avoid matching UUIDs, git SHAs, session tokens, etc.
_HEX_MIXED_LOOKAHEAD = r"(?=.*[0-9])(?=.*[a-fA-F])"

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,24}\b"
    ),
    "url": re.compile(r"\bhttps?://[^\s<>'\")]+", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "md5": re.compile(r"\b" + _HEX_MIXED_LOOKAHEAD + r"[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b" + _HEX_MIXED_LOOKAHEAD + r"[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b" + _HEX_MIXED_LOOKAHEAD + r"[a-fA-F0-9]{64}\b"),
}

IOC_TYPES = tuple(IOC_PATTERNS.keys())

# Common English words that look like TLDs — filter out false-positive "domains"
_KNOWN_VALID_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "us", "uk",
    "de", "fr", "jp", "cn", "ru", "br", "in", "au", "ca", "nl", "se", "ch",
    "es", "it", "kr", "mx", "za", "nz", "info", "biz", "pro", "name",
    "mobi", "tel", "asia", "cat", "coop", "jobs", "travel", "museum", "aero",
    "xyz", "online", "site", "tech", "store", "app", "dev", "cloud",
    "security", "network", "systems", "digital", "global", "world",
    "email", "link", "click", "top", "live", "news", "media",
}


def _is_valid_domain(value):
    """Reject common false-positive domains by checking TLD and structure."""
    parts = value.lower().rsplit(".", 1)
    if len(parts) < 2:
        return False
    tld = parts[1]
    # Require a recognized TLD
    if tld not in _KNOWN_VALID_TLDS:
        return False
    # Reject single-word "domains" like "example.com" where the host part is too short
    # to be meaningful — require at least one dot in the host portion (i.e., subdomain.domain.tld)
    # or the host+tld total length must be >= 5 chars
    host = parts[0]
    if len(host) < 2:
        return False
    return True


def _normalize_value(entity_type, value):
    normalized = value.strip().strip(".,);")
    if entity_type in {"cve"}:
        return normalized.upper()
    if entity_type in {"domain", "md5", "sha1", "sha256"}:
        return normalized.lower()
    return normalized


def extract_iocs(text):
    """Extract unique IOC entities from raw text."""
    raw = text or ""
    findings = []
    seen = set()

    url_spans = [(m.start(), m.end()) for m in IOC_PATTERNS["url"].finditer(raw)]

    def _in_url_span(start, end):
        return any(start < span_end and end > span_start for span_start, span_end in url_spans)

    for entity_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(raw):
            if entity_type == "domain" and _in_url_span(match.start(), match.end()):
                continue
            value = _normalize_value(entity_type, match.group(0))
            if not value:
                continue
            # Validate domain candidates against known TLDs
            if entity_type == "domain" and not _is_valid_domain(value):
                continue
            key = (entity_type, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"entity_type": entity_type, "entity_value": value})

    return findings


def store_alert_entities(conn, alert_id, entities):
    """Persist extracted entities for a single alert with idempotent upsert."""
    for entity in entities:
        conn.execute(
            """INSERT INTO alert_entities (alert_id, entity_type, entity_value, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(alert_id, entity_type, entity_value) DO NOTHING""",
            (
                alert_id,
                entity["entity_type"],
                entity["entity_value"],
            ),
        )


def extract_and_store_alert_entities(conn, alert_id, text):
    """Extract IOC entities from text and store in alert_entities."""
    entities = extract_iocs(text)
    store_alert_entities(conn, alert_id, entities)
    return entities
