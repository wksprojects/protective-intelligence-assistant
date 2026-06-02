#!/usr/bin/env python3
"""Generate a public-data travel advisory case study from official RSS feeds."""

from __future__ import annotations

import csv
import html
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "outputs"
DOCS_DIR = ROOT / "docs"

STATE_RSS = "https://travel.state.gov/_res/rss/TAsTWs.xml"
CDC_RSS = "https://wwwnc.cdc.gov/travel/rss/notices.xml"

SOURCE_ROWS_PATH = OUT_DIR / "public_travel_advisory_source_rows.csv"
QUEUE_PATH = OUT_DIR / "public_travel_advisory_review_queue.csv"
ROLLUP_PATH = OUT_DIR / "public_travel_advisory_rollup.csv"
CASE_STUDY_PATH = DOCS_DIR / "public_travel_advisory_case_study.md"

RISK_TERMS = {
    "terrorism": 10,
    "terrorist": 10,
    "unrest": 8,
    "civil unrest": 8,
    "crime": 7,
    "kidnapping": 9,
    "armed conflict": 10,
    "wrongful detention": 9,
    "do not travel": 12,
    "reconsider travel": 10,
    "ebola": 12,
    "outbreak": 8,
    "dengue": 6,
    "chikungunya": 6,
    "measles": 6,
}


@dataclass(frozen=True)
class AdvisoryRow:
    source: str
    source_url: str
    title: str
    published_at: str
    link: str
    destination: str
    advisory_level: int
    priority: str
    risk_score: int
    risk_terms: str
    summary: str


def _fetch_feed(url: str) -> list[dict[str, str]]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "protective-intelligence-assistant-public-case-study/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    root = ET.fromstring(payload)
    rows = []
    for item in root.findall(".//item"):
        rows.append(
            {
                "title": _clean_text(item.findtext("title")),
                "description": _clean_text(item.findtext("description")),
                "published_at": _parse_date(item.findtext("pubDate")),
                "link": _clean_text(item.findtext("link")),
            }
        )
    return rows


def _clean_text(value: str | None) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _parse_date(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return value.strip()
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d")


def _extract_level(title: str, description: str) -> int:
    text = f"{title} {description}"
    match = re.search(r"\bLevel\s*(\d)\b", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    if re.search(r"\bdo not travel\b", text, flags=re.IGNORECASE):
        return 4
    if re.search(r"\breconsider travel\b", text, flags=re.IGNORECASE):
        return 3
    return 0


def _extract_destination(source: str, title: str) -> str:
    if source == "state_dept":
        title = re.sub(r"\s+Travel Advisory\b", "", title, flags=re.IGNORECASE)
        return re.split(r"\s+-\s+Level\s*\d", title, maxsplit=1)[0].strip()

    if " in " in title:
        return title.rsplit(" in ", maxsplit=1)[-1].strip()
    return title


def _priority_for(source: str, level: int, score: int) -> str:
    if source == "state_dept" and level >= 4:
        return "critical"
    if source == "cdc" and level >= 3:
        return "critical"
    if level >= 3 or score >= 70:
        return "high"
    if level >= 2 or score >= 45:
        return "medium"
    return "low"


def _risk_terms(text: str) -> tuple[int, list[str]]:
    text_lower = text.lower()
    hits = []
    score = 0
    for term, weight in RISK_TERMS.items():
        if term in text_lower:
            hits.append(term)
            score += weight
    return score, sorted(set(hits))


def _score(source: str, level: int, title: str, description: str) -> tuple[int, str, str]:
    term_score, terms = _risk_terms(f"{title} {description}")
    base = 15 if source == "state_dept" else 12
    level_score = level * 14 if level else 8
    score = min(100, base + level_score + term_score)
    priority = _priority_for(source, level, score)
    return score, priority, "; ".join(terms) if terms else "level/context only"


def _build_rows() -> list[AdvisoryRow]:
    all_rows: list[AdvisoryRow] = []
    sources = [
        ("state_dept", "U.S. Department of State Travel Advisories", STATE_RSS),
        ("cdc", "CDC Travel Health Notices", CDC_RSS),
    ]
    for source_id, source_name, source_url in sources:
        for row in _fetch_feed(source_url):
            level = _extract_level(row["title"], row["description"])
            score, priority, terms = _score(source_id, level, row["title"], row["description"])
            all_rows.append(
                AdvisoryRow(
                    source=source_name,
                    source_url=source_url,
                    title=row["title"],
                    published_at=row["published_at"],
                    link=row["link"],
                    destination=_extract_destination(source_id, row["title"]),
                    advisory_level=level,
                    priority=priority,
                    risk_score=score,
                    risk_terms=terms,
                    summary=row["description"][:320].strip(),
                )
            )
    return sorted(all_rows, key=lambda item: (-item.risk_score, item.source, item.destination))


def _write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _queue_rows(rows: list[AdvisoryRow]) -> list[dict[str, object]]:
    queue = [row for row in rows if row.priority in {"critical", "high", "medium"}]
    output = []
    for idx, row in enumerate(queue, start=1):
        output.append(
            {
                "queue_id": f"PTA-{idx:03d}",
                "priority": row.priority,
                "source": row.source,
                "destination_or_notice": row.destination,
                "advisory_level": row.advisory_level,
                "risk_score": row.risk_score,
                "risk_terms": row.risk_terms,
                "published_at": row.published_at,
                "recommended_review": _review_action(row),
                "source_url": row.link,
            }
        )
    return output


def _review_action(row: AdvisoryRow) -> str:
    if row.priority == "critical":
        return "Require analyst review before travel planning or itinerary approval."
    if row.priority == "high":
        return "Validate itinerary relevance and identify exposure controls."
    if row.priority == "medium":
        return "Track for destination context and pre-travel brief inclusion."
    return "Archive as baseline context."


def _rollup_rows(rows: list[AdvisoryRow]) -> list[dict[str, object]]:
    counter = Counter((row.source, row.advisory_level, row.priority) for row in rows)
    output = []
    for (source, level, priority), count in sorted(counter.items()):
        output.append(
            {
                "source": source,
                "advisory_level": level,
                "priority": priority,
                "count": count,
            }
        )
    return output


def _render_case_study(rows: list[AdvisoryRow], queue: list[dict[str, object]]) -> str:
    counts = Counter(row.source for row in rows)
    priorities = Counter(row.priority for row in rows)
    level_counts = Counter(row.advisory_level for row in rows)
    top_queue = queue[:10]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    queue_lines = "\n".join(
        "| {queue_id} | {priority} | {source} | {destination_or_notice} | {advisory_level} | {risk_score} | {recommended_review} |".format(
            **item
        )
        for item in top_queue
    )

    return f"""# Public Travel Advisory Case Study

Generated: {generated_at}
Data class: official public RSS feeds
Disposition: review queue inputs, not threat findings

## Dataset

This companion case study uses official public travel-risk feeds to demonstrate how the Protective Intelligence Assistant can turn public context into reviewable outputs for travel and protective-intelligence planning.

| Source | Rows | Feed |
|---|---:|---|
| U.S. Department of State Travel Advisories | {counts.get("U.S. Department of State Travel Advisories", 0)} | {STATE_RSS} |
| CDC Travel Health Notices | {counts.get("CDC Travel Health Notices", 0)} | {CDC_RSS} |
| Total | {len(rows)} | two official public RSS feeds |

## Output Metrics

| Metric | Count |
|---|---:|
| Critical review items | {priorities.get("critical", 0)} |
| High review items | {priorities.get("high", 0)} |
| Medium review items | {priorities.get("medium", 0)} |
| Level 4 / equivalent notices | {level_counts.get(4, 0)} |
| Level 3 / equivalent notices | {level_counts.get(3, 0)} |
| Level 2 / equivalent notices | {level_counts.get(2, 0)} |

## Workflow

1. Fetch official public RSS rows from State Department and CDC feeds.
2. Normalize each item into source, destination or notice, published date, advisory level, and URL.
3. Score rows using advisory level and keyword context such as terrorism, unrest, crime, kidnapping, outbreak, and disease indicators.
4. Route critical, high, and medium rows into an analyst review queue.
5. Produce rollups by source, advisory level, and priority for quick briefing.

## Representative Review Queue

| Queue ID | Priority | Source | Destination or Notice | Level | Score | Recommended Review |
|---|---|---|---|---:|---:|---|
{queue_lines}

Full outputs:

- `outputs/public_travel_advisory_source_rows.csv`
- `outputs/public_travel_advisory_review_queue.csv`
- `outputs/public_travel_advisory_rollup.csv`

## Scope and Limitations

- These rows are official public advisories and health notices, not private intelligence or law-enforcement reporting.
- Scores are triage aids for review priority; they do not establish a specific threat to a person, organization, route, or event.
- Advisory relevance still depends on itinerary, traveler profile, timing, local movement, venue exposure, and operational context.
- The feed snapshot can change as agencies update or remove advisories.
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    rows = _build_rows()
    queue = _queue_rows(rows)
    rollup = _rollup_rows(rows)

    _write_csv(
        SOURCE_ROWS_PATH,
        [row.__dict__ for row in rows],
        [
            "source",
            "source_url",
            "title",
            "published_at",
            "link",
            "destination",
            "advisory_level",
            "priority",
            "risk_score",
            "risk_terms",
            "summary",
        ],
    )
    _write_csv(
        QUEUE_PATH,
        queue,
        [
            "queue_id",
            "priority",
            "source",
            "destination_or_notice",
            "advisory_level",
            "risk_score",
            "risk_terms",
            "published_at",
            "recommended_review",
            "source_url",
        ],
    )
    _write_csv(ROLLUP_PATH, rollup, ["source", "advisory_level", "priority", "count"])
    CASE_STUDY_PATH.write_text(_render_case_study(rows, queue), encoding="utf-8")

    print(f"Generated {len(rows)} public source rows")
    print(f"Generated {len(queue)} review queue rows")
    print(f"Generated {len(rollup)} rollup rows")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"public travel advisory case study generation failed: {exc}", file=sys.stderr)
        raise
