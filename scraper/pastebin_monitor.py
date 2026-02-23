import requests
from bs4 import BeautifulSoup

from analytics.dedup import check_duplicate
from analytics.ep_pipeline import process_ep_signals
from analytics.entity_extraction import extract_and_store_alert_entities
from analytics.risk_scoring import (
    build_frequency_snapshot,
    increment_keyword_frequency,
    score_alert,
)
from database.init_db import get_connection
from scraper.rss_scraper import alert_exists, get_active_keywords, match_keywords
from scraper.source_health import mark_source_failure, mark_source_success

PASTEBIN_ARCHIVE_URL = "https://pastebin.com/archive"


def fetch_recent_pastes():
    """Scrape pastebin archive page for recent public pastes."""
    entries = []
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(PASTEBIN_ARCHIVE_URL, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table", class_="maintable")
        if not table:
            print("No paste table found.")
            return entries

        rows = table.find_all("tr")[1:]  # skip header
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 1:
                link = cols[0].find("a")
                if link:
                    paste_id = link.get("href", "").strip("/")
                    title = link.text.strip() or "Untitled"
                    entries.append(
                        {
                            "title": title,
                            "url": f"https://pastebin.com/{paste_id}",
                            "paste_id": paste_id,
                        }
                    )
    except requests.RequestException as e:
        print(f"Error fetching pastebin archive: {e}")

    return entries


def fetch_paste_content(url):
    """Fetch raw content of a specific paste."""
    try:
        raw_url = url.replace("pastebin.com/", "pastebin.com/raw/")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text[:5000]
    except requests.RequestException as e:
        print(f"Error fetching paste content: {e}")
        return ""


def ensure_pastebin_source(conn):
    """Make sure pastebin exists as a source in the DB."""
    cursor = conn.execute("SELECT id FROM sources WHERE name = 'Pastebin Archive'")
    row = cursor.fetchone()
    if row:
        return row["id"]

    conn.execute(
        "INSERT INTO sources (name, url, source_type, credibility_score) VALUES (?, ?, ?, ?)",
        ("Pastebin Archive", PASTEBIN_ARCHIVE_URL, "pastebin", 0.2),
    )
    conn.commit()
    cursor = conn.execute("SELECT id FROM sources WHERE name = 'Pastebin Archive'")
    return cursor.fetchone()["id"]


def run_pastebin_scraper(frequency_snapshot=None):
    conn = get_connection()
    try:
        keywords = get_active_keywords(conn)
        if frequency_snapshot is None:
            frequency_snapshot = build_frequency_snapshot(
                conn, keyword_ids=[keyword["id"] for keyword in keywords]
            )
        source_id = ensure_pastebin_source(conn)
        new_alerts = 0
        duplicates = 0

        print("Scraping: Pastebin Archive")
        pastes = fetch_recent_pastes()
        if not pastes:
            mark_source_failure(conn, source_id, "pastebin archive returned no pastes")
            conn.commit()
            print("Pastebin scrape complete. 0 new alerts, 0 duplicates skipped.")
            return 0

        for paste in pastes[:20]:  # limit to avoid rate limiting
            content = fetch_paste_content(paste["url"])
            if not content:
                continue

            combined_text = f"{paste['title']} {content}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source_id, keyword["id"], paste["url"]):
                    content_hash, duplicate_of = check_duplicate(conn, paste["title"], content)
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, published_at, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            source_id,
                            keyword["id"],
                            paste["title"],
                            content[:2000],
                            paste["url"],
                            keyword["term"],
                            content_hash,
                            duplicate_of,
                            None,
                            "low",
                        ),
                    )
                    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                    if duplicate_of is None:
                        score_args = frequency_snapshot.get(keyword["id"])
                        baseline_score = score_alert(
                            conn,
                            alert_id,
                            keyword["id"],
                            source_id,
                            frequency_override=score_args[0] if score_args else None,
                            z_score_override=score_args[1] if score_args else None,
                        )
                        extract_and_store_alert_entities(
                            conn, alert_id, f"{paste['title']}\n{content}"
                        )
                        process_ep_signals(
                            conn,
                            alert_id=alert_id,
                            title=paste["title"],
                            content=content,
                            keyword_category=keyword.get("category"),
                            baseline_score=baseline_score,
                        )
                        increment_keyword_frequency(conn, keyword["id"])
                        new_alerts += 1
                    else:
                        duplicates += 1

        mark_source_success(conn, source_id)
        conn.commit()
        print(f"Pastebin scrape complete. {new_alerts} new alerts, {duplicates} duplicates skipped.")
        return new_alerts
    except Exception as exc:
        source_id = ensure_pastebin_source(conn)
        mark_source_failure(conn, source_id, f"pastebin collector error: {exc!r}")
        conn.commit()
        print(f"Pastebin scrape failed: {exc}")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    run_pastebin_scraper()
