"""Correlation-engine pairwise evaluation on hand-labeled cases."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from datetime import timedelta
from itertools import combinations
from pathlib import Path

from analytics.utils import utcnow
from database import init_db as db_init
from processor.correlation import build_incident_threads

DEFAULT_DATASET_PATH = Path("fixtures/correlation_eval_cases.json")


def _precision(tp, fp):
    return tp / (tp + fp) if (tp + fp) else 0.0


def _recall(tp, fn):
    return tp / (tp + fn) if (tp + fn) else 0.0


def _f1(precision, recall):
    return (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


def _norm_pair(left, right):
    return (left, right) if left <= right else (right, left)


@contextmanager
def _isolated_db():
    old_db_path = db_init.DB_PATH
    fd, temp_db_path = tempfile.mkstemp(prefix="pi_corr_eval_", suffix=".db")
    os.close(fd)
    try:
        db_init.DB_PATH = temp_db_path
        yield
    finally:
        db_init.DB_PATH = old_db_path
        try:
            os.remove(temp_db_path)
        except OSError:
            pass


def _load_cases(dataset_path):
    payload = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise ValueError("Correlation eval dataset has no cases.")
    return payload.get("description", ""), cases


def _upsert_source(conn, source_type):
    name = f"eval-{source_type}"
    url = f"https://eval.local/{source_type}"
    row = conn.execute(
        "SELECT id FROM sources WHERE name = ? AND source_type = ?",
        (name, source_type),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        """INSERT INTO sources (name, url, source_type, credibility_score, active)
        VALUES (?, ?, ?, ?, 1)""",
        (name, url, source_type, 0.6),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _upsert_keyword(conn, term):
    clean = str(term or "").strip().lower()
    if not clean:
        clean = "general"
    row = conn.execute(
        "SELECT id FROM keywords WHERE term = ?",
        (clean,),
    ).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        "INSERT INTO keywords (term, category, weight, active) VALUES (?, 'protective_intel', 2.0, 1)",
        (clean,),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _upsert_poi(conn, poi_name):
    clean = str(poi_name or "").strip()
    if not clean:
        return None
    row = conn.execute("SELECT id FROM pois WHERE name = ?", (clean,)).fetchone()
    if row:
        return int(row["id"])
    conn.execute(
        "INSERT INTO pois (name, org, role, sensitivity, active) VALUES (?, 'Eval Org', 'Principal', 5, 1)",
        (clean,),
    )
    poi_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    conn.execute(
        """INSERT OR IGNORE INTO poi_aliases (poi_id, alias, alias_type, active)
        VALUES (?, ?, 'name', 1)""",
        (poi_id, clean),
    )
    return poi_id


def _insert_case_alerts(conn, case):
    now_dt = utcnow()
    label_to_alert_id = {}
    case_labels = []
    for idx, alert in enumerate(case.get("alerts") or [], start=1):
        label = str(alert.get("id") or f"a{idx}")
        source_type = str(alert.get("source_type") or "rss").strip().lower() or "rss"
        source_id = _upsert_source(conn, source_type)
        keyword_id = _upsert_keyword(conn, alert.get("matched_term") or "general")
        hours_ago = max(0.0, float(alert.get("hours_ago") or 0.0))
        published_at = (now_dt - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")

        url = str(alert.get("url") or f"https://eval.local/{case['id']}/{label}").strip()
        title = str(alert.get("title") or f"Eval alert {label}")
        content = str(alert.get("content") or "")
        matched_term = str(alert.get("matched_term") or "general")

        conn.execute(
            """INSERT INTO alerts
            (source_id, keyword_id, title, content, url, matched_term, published_at, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'low')""",
            (source_id, keyword_id, title, content, url, matched_term, published_at),
        )
        alert_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        label_to_alert_id[label] = alert_id
        case_labels.append(label)

        actor_handles = alert.get("actor_handles") or []
        for handle in actor_handles:
            clean = str(handle or "").strip().lower()
            if clean:
                conn.execute(
                    """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
                    VALUES (?, 'actor_handle', ?, CURRENT_TIMESTAMP)""",
                    (alert_id, clean),
                )

        entities = alert.get("entities") or []
        for entity in entities:
            etype = str(entity.get("entity_type") or "").strip().lower()
            evalue = str(entity.get("entity_value") or "").strip().lower()
            if etype and evalue:
                conn.execute(
                    """INSERT OR IGNORE INTO alert_entities (alert_id, entity_type, entity_value, created_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                    (alert_id, etype, evalue),
                )

        poi_names = alert.get("poi_names") or []
        for poi_name in poi_names:
            poi_id = _upsert_poi(conn, poi_name)
            if poi_id is None:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO poi_hits
                (poi_id, alert_id, match_type, match_value, match_score, context)
                VALUES (?, ?, 'name', ?, 1.0, 'eval-case')""",
                (poi_id, alert_id, str(poi_name)),
            )

    conn.commit()
    return label_to_alert_id, case_labels


def _pairs_from_threads(threads, alert_id_to_label):
    predicted = set()
    for thread in threads:
        labels = []
        for row in thread.get("timeline", []):
            label = alert_id_to_label.get(int(row.get("alert_id")))
            if label:
                labels.append(label)
        for left, right in combinations(sorted(set(labels)), 2):
            predicted.add(_norm_pair(left, right))
    return predicted


def _evaluate_case(case):
    with _isolated_db():
        db_init.init_db()
        db_init.migrate_schema()
        conn = db_init.get_connection()
        try:
            label_to_alert_id, labels = _insert_case_alerts(conn, case)
        finally:
            conn.close()

        alert_id_to_label = {v: k for k, v in label_to_alert_id.items()}
        window_hours = int(case.get("window_hours") or 72)
        threads = build_incident_threads(
            days=30,
            window_hours=window_hours,
            min_cluster_size=2,
            limit=100,
            include_demo=True,
        )
        predicted_pairs = _pairs_from_threads(threads, alert_id_to_label)
        expected_pairs = {
            _norm_pair(str(pair[0]), str(pair[1]))
            for pair in (case.get("expected_linked_pairs") or [])
            if isinstance(pair, list) and len(pair) == 2
        }
        all_pairs = {_norm_pair(left, right) for left, right in combinations(sorted(set(labels)), 2)}

        tp = len(predicted_pairs & expected_pairs)
        fp = len(predicted_pairs - expected_pairs)
        fn = len(expected_pairs - predicted_pairs)
        tn = len(all_pairs - (predicted_pairs | expected_pairs))

        return {
            "id": case.get("id", "unknown_case"),
            "alerts": len(labels),
            "pairs_total": len(all_pairs),
            "expected_pairs": len(expected_pairs),
            "predicted_pairs": len(predicted_pairs),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(_precision(tp, fp), 4),
            "recall": round(_recall(tp, fn), 4),
            "f1": round(_f1(_precision(tp, fp), _recall(tp, fn)), 4),
            "exact_match": predicted_pairs == expected_pairs,
        }


def run_correlation_engine_evaluation(dataset_path=DEFAULT_DATASET_PATH):
    description, cases = _load_cases(dataset_path)
    case_rows = [_evaluate_case(case) for case in cases]

    tp = sum(row["tp"] for row in case_rows)
    fp = sum(row["fp"] for row in case_rows)
    fn = sum(row["fn"] for row in case_rows)
    tn = sum(row["tn"] for row in case_rows)

    precision = _precision(tp, fp)
    recall = _recall(tp, fn)
    f1 = _f1(precision, recall)

    return {
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_path": str(dataset_path),
        "dataset_description": description,
        "cases_total": len(case_rows),
        "exact_match_cases": sum(1 for row in case_rows if row["exact_match"]),
        "pair_totals": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "support_positive_pairs": tp + fn,
            "support_all_pairs": tp + fp + fn + tn,
        },
        "aggregate": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "cases": case_rows,
    }


def render_correlation_engine_eval_markdown(report):
    aggregate = report["aggregate"]
    totals = report["pair_totals"]
    lines = [
        "# Correlation Engine Evaluation",
        "",
        f"Generated: {report['generated_at']} UTC",
        f"Dataset: `{report['dataset_path']}`",
        f"Cases: **{report['cases_total']}** (exact-match cases: **{report['exact_match_cases']}**)",
        "",
        "## Aggregate Pairwise Metrics",
        f"- Precision: **{aggregate['precision']:.4f}**",
        f"- Recall: **{aggregate['recall']:.4f}**",
        f"- F1: **{aggregate['f1']:.4f}**",
        f"- Support (positive pairs): **{totals['support_positive_pairs']}**",
        "",
        "## Pair Confusion Totals",
        "| TP | FP | FN | TN | Total Pairs |",
        "|---:|---:|---:|---:|---:|",
        (
            f"| {totals['tp']} | {totals['fp']} | {totals['fn']} | "
            f"{totals['tn']} | {totals['support_all_pairs']} |"
        ),
        "",
        "## Per-Case Metrics",
        "| Case | Alerts | Expected Pairs | Predicted Pairs | TP | FP | FN | Precision | Recall | F1 | Exact Match |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["cases"]:
        lines.append(
            (
                f"| {row['id']} | {row['alerts']} | {row['expected_pairs']} | {row['predicted_pairs']} | "
                f"{row['tp']} | {row['fp']} | {row['fn']} | {row['precision']:.4f} | "
                f"{row['recall']:.4f} | {row['f1']:.4f} | {1 if row['exact_match'] else 0} |"
            )
        )
    lines.append("")
    return "\n".join(lines)
