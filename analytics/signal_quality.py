"""Signal quality metrics for source/category ROI tracking."""

from collections import defaultdict
from datetime import timedelta

from analytics.utils import utcnow
from database.init_db import get_connection

_TP_STATUSES = {"true_positive"}
_FP_STATUSES = {"false_positive"}
_CLASSIFIED_STATUSES = _TP_STATUSES | _FP_STATUSES


def _precision(tp, fp):
    denom = tp + fp
    if denom <= 0:
        return None
    return round(tp / denom, 4)


def compute_signal_quality(window_days=30, include_demo=False):
    safe_window_days = max(7, min(int(window_days), 365))
    cutoff = (utcnow() - timedelta(days=safe_window_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    demo_filter = ""
    if not include_demo:
        demo_filter = " AND COALESCE(s.source_type, '') != 'demo'"

    try:
        status_rows = conn.execute(
            f"""SELECT d.status,
                      d.created_at,
                      s.id AS source_id,
                      s.name AS source_name,
                      k.category AS keyword_category
            FROM dispositions d
            JOIN alerts a ON a.id = d.alert_id
            LEFT JOIN sources s ON s.id = a.source_id
            LEFT JOIN keywords k ON k.id = a.keyword_id
            WHERE datetime(d.created_at) >= datetime(?)
              AND d.status IN ('true_positive', 'false_positive')
              {demo_filter}""",
            (cutoff,),
        ).fetchall()

        overall_tp = 0
        overall_fp = 0
        source_counts = defaultdict(lambda: {"tp": 0, "fp": 0, "source_name": None})
        category_counts = defaultdict(lambda: {"tp": 0, "fp": 0})
        daily_counts = defaultdict(lambda: {"tp": 0, "fp": 0})

        for row in status_rows:
            status = (row["status"] or "").strip().lower()
            date_key = str(row["created_at"] or "")[:10]
            source_id = int(row["source_id"]) if row["source_id"] is not None else None
            source_name = row["source_name"] or "unknown"
            category = row["keyword_category"] or "unknown"

            if status in _TP_STATUSES:
                overall_tp += 1
                if source_id is not None:
                    source_counts[source_id]["tp"] += 1
                category_counts[category]["tp"] += 1
                daily_counts[date_key]["tp"] += 1
            elif status in _FP_STATUSES:
                overall_fp += 1
                if source_id is not None:
                    source_counts[source_id]["fp"] += 1
                category_counts[category]["fp"] += 1
                daily_counts[date_key]["fp"] += 1

            if source_id is not None:
                source_counts[source_id]["source_name"] = source_name

        by_source_window = []
        for source_id, stats in source_counts.items():
            tp = int(stats["tp"])
            fp = int(stats["fp"])
            by_source_window.append(
                {
                    "source_id": source_id,
                    "source_name": stats["source_name"] or "unknown",
                    "true_positive": tp,
                    "false_positive": fp,
                    "classified": tp + fp,
                    "precision": _precision(tp, fp),
                }
            )
        by_source_window.sort(key=lambda row: (row["classified"], row["precision"] or 0.0), reverse=True)

        by_category_window = []
        for category, stats in category_counts.items():
            tp = int(stats["tp"])
            fp = int(stats["fp"])
            by_category_window.append(
                {
                    "category": category,
                    "true_positive": tp,
                    "false_positive": fp,
                    "classified": tp + fp,
                    "precision": _precision(tp, fp),
                }
            )
        by_category_window.sort(
            key=lambda row: (row["classified"], row["precision"] or 0.0),
            reverse=True,
        )

        daily = []
        for date_key in sorted(daily_counts.keys()):
            tp = int(daily_counts[date_key]["tp"])
            fp = int(daily_counts[date_key]["fp"])
            daily.append(
                {
                    "date": date_key,
                    "true_positive": tp,
                    "false_positive": fp,
                    "classified": tp + fp,
                    "precision": _precision(tp, fp),
                }
            )

        lifetime_rows = conn.execute(
            f"""SELECT id AS source_id, name AS source_name,
                      COALESCE(true_positives, 0) AS true_positives,
                      COALESCE(false_positives, 0) AS false_positives,
                      credibility_score,
                      fail_streak,
                      last_status
            FROM sources s
            WHERE 1=1 {demo_filter}
            ORDER BY name"""
        ).fetchall()
        lifetime = []
        for row in lifetime_rows:
            tp = int(row["true_positives"] or 0)
            fp = int(row["false_positives"] or 0)
            lifetime.append(
                {
                    "source_id": int(row["source_id"]),
                    "source_name": row["source_name"],
                    "true_positive": tp,
                    "false_positive": fp,
                    "classified": tp + fp,
                    "precision": _precision(tp, fp),
                    "bayesian_credibility": round(float(row["credibility_score"] or 0.0), 4),
                    "fail_streak": int(row["fail_streak"] or 0),
                    "last_status": row["last_status"] or "unknown",
                }
            )

        return {
            "as_of": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "window_days": safe_window_days,
            "overall_window": {
                "true_positive": overall_tp,
                "false_positive": overall_fp,
                "classified": overall_tp + overall_fp,
                "precision": _precision(overall_tp, overall_fp),
            },
            "by_source_window": by_source_window,
            "by_category_window": by_category_window,
            "daily_window": daily,
            "source_lifetime": lifetime,
        }
    finally:
        conn.close()
