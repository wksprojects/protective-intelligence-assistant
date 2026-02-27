"""
Risk Scoring Engine for Protective Intelligence Assistant.

Statistical approach:
- Z-score anomaly detection for keyword frequency spikes
- Bayesian credibility updating for source trustworthiness
- Multi-factor scoring with audit trail

Formula: risk_score = (keyword_weight * z_score_factor * bayesian_credibility * 20) + recency_bonus
Clamped to 0-100 range.

Severity derivation:
  90-100 = critical
  70-89  = high
  40-69  = medium
  0-39   = low
"""

from datetime import timedelta

from analytics.utils import compute_recency_factor, utcnow


def compute_risk_score(keyword_weight, source_credibility, frequency_factor, recency_hours):
    """
    Compute a 0-100 risk score and derive severity.

    Args:
        keyword_weight: Weight of the matched keyword (0.1-5.0)
        source_credibility: Bayesian credibility of the source (0.0-1.0)
        frequency_factor: Z-score-derived multiplier (1.0-4.0)
        recency_hours: Hours since the source event was published

    Returns:
        (risk_score, severity) tuple
    """
    recency_factor = max(0.1, 1.0 - (max(0.0, recency_hours) / 168.0))
    raw_score = (keyword_weight * frequency_factor * source_credibility * 20.0) + (
        recency_factor * 10.0
    )
    risk_score = round(min(100.0, max(0.0, raw_score)), 1)
    severity = score_to_severity(risk_score)
    return risk_score, severity


def score_to_severity(score):
    """Map numeric score to severity label."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def score_to_severity_with_uncertainty(point_score, interval_mean=None):
    """Map score to severity, preferring the uncertainty interval mean when available.

    When Monte Carlo intervals exist, severity is derived from the interval
    mean rather than the point estimate.  This avoids oscillation near
    severity boundaries (e.g. 89.9 vs 90.0).

    Returns:
        (severity, used_score) tuple.
    """
    used_score = interval_mean if interval_mean is not None else point_score
    return score_to_severity(used_score), used_score


def get_keyword_weight(conn, keyword_id):
    """Fetch keyword weight from database, defaulting to 1.0."""
    row = conn.execute("SELECT weight FROM keywords WHERE id = ?", (keyword_id,)).fetchone()
    return row["weight"] if row and row["weight"] else 1.0


def get_source_credibility(conn, source_id):
    """
    Bayesian credibility using Beta distribution.
    credibility = alpha / (alpha + beta)
    Falls back to static credibility_score if no TP/FP data exists.
    """
    row = conn.execute(
        """SELECT credibility_score, bayesian_alpha, bayesian_beta,
                  true_positives, false_positives
           FROM sources WHERE id = ?""",
        (source_id,),
    ).fetchone()
    if not row:
        return 0.5

    alpha = row["bayesian_alpha"] if row["bayesian_alpha"] else 2.0
    beta = row["bayesian_beta"] if row["bayesian_beta"] else 2.0

    # If no TP/FP classifications yet, use static score
    if (row["true_positives"] or 0) == 0 and (row["false_positives"] or 0) == 0:
        return row["credibility_score"] if row["credibility_score"] else 0.5

    return round(alpha / (alpha + beta), 4)


def get_frequency_factor(conn, keyword_id):
    """
    Z-score based frequency factor.
    z = (today_count - mean_7d) / std_dev_7d
    Maps z-score to a multiplier 1.0-4.0.
    Falls back to simple ratio when < 3 days of data.

    Returns:
        (frequency_factor, z_score) tuple
    """
    today = utcnow().strftime("%Y-%m-%d")
    today_row = conn.execute(
        "SELECT count FROM keyword_frequency WHERE keyword_id = ? AND date = ?",
        (keyword_id, today),
    ).fetchone()
    today_count = today_row["count"] if today_row else 0

    seven_days_ago = (utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    rows = conn.execute(
        """SELECT count FROM keyword_frequency
        WHERE keyword_id = ? AND date >= ? AND date < ?""",
        (keyword_id, seven_days_ago, today),
    ).fetchall()

    counts = [row["count"] for row in rows]

    if len(counts) < 3:
        # Fallback to simple ratio for insufficient data
        avg = sum(counts) / len(counts) if counts else 1.0
        avg = max(avg, 1.0)
        ratio = today_count / avg
        return max(1.0, round(ratio, 2)), 0.0

    mean = sum(counts) / len(counts)
    # Use sample variance (Bessel's correction) for small N to avoid
    # underestimating variance and inflating Z-scores.
    variance = sum((c - mean) ** 2 for c in counts) / (len(counts) - 1)
    std_dev = variance**0.5

    if std_dev < 0.5:
        std_dev = 0.5  # Floor to prevent division-by-near-zero

    z_score = (today_count - mean) / std_dev

    # Map z-score to multiplier: 1.0 at z<=0, 4.0 at z>=4
    if z_score <= 0:
        factor = 1.0
    elif z_score >= 4.0:
        factor = 4.0
    else:
        factor = round(1.0 + (z_score * 0.75), 2)

    return factor, round(z_score, 2)


def build_frequency_snapshot(conn, keyword_ids=None):
    """Build a keyword -> (frequency_factor, z_score) snapshot for a scoring cycle."""
    if keyword_ids is None:
        rows = conn.execute("SELECT id FROM keywords WHERE active = 1").fetchall()
        keyword_ids = [row["id"] for row in rows]
    return {keyword_id: get_frequency_factor(conn, keyword_id) for keyword_id in keyword_ids}


def increment_keyword_frequency(conn, keyword_id, increment_by=1):
    """Increment today's frequency count for a keyword."""
    if increment_by <= 0:
        return
    today = utcnow().strftime("%Y-%m-%d")
    conn.execute(
        """INSERT INTO keyword_frequency (keyword_id, date, count)
        VALUES (?, ?, ?)
        ON CONFLICT(keyword_id, date)
        DO UPDATE SET count = count + excluded.count""",
        (keyword_id, today, increment_by),
    )


def score_alert(
    conn,
    alert_id,
    keyword_id,
    source_id,
    created_at=None,
    published_at=None,
    frequency_override=None,
    z_score_override=None,
):
    """
    Full scoring pipeline for a single alert.
    Computes score, updates alert, and stores audit trail in alert_scores.
    Returns the final risk score.
    """
    keyword_weight = get_keyword_weight(conn, keyword_id)
    source_credibility = get_source_credibility(conn, source_id)
    if frequency_override is not None:
        frequency_factor = frequency_override
        z_score = z_score_override if z_score_override is not None else 0.0
    else:
        frequency_factor, z_score = get_frequency_factor(conn, keyword_id)

    recency_factor, recency_hours = compute_recency_factor(
        published_at=published_at, created_at=created_at
    )

    risk_score, severity = compute_risk_score(
        keyword_weight, source_credibility, frequency_factor, recency_hours
    )
    conn.execute(
        "UPDATE alerts SET risk_score = ?, severity = ? WHERE id = ?",
        (risk_score, severity, alert_id),
    )
    conn.execute(
        """INSERT INTO alert_scores
        (alert_id, keyword_weight, source_credibility, frequency_factor, z_score, recency_factor, final_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            alert_id,
            keyword_weight,
            source_credibility,
            frequency_factor,
            z_score,
            recency_factor,
            risk_score,
        ),
    )
    return risk_score


def _batch_keyword_weights(conn, keyword_ids):
    """Fetch keyword weights in bulk. Returns {keyword_id: weight}."""
    if not keyword_ids:
        return {}
    placeholders = ",".join("?" for _ in keyword_ids)
    rows = conn.execute(
        f"SELECT id, weight FROM keywords WHERE id IN ({placeholders})",
        list(keyword_ids),
    ).fetchall()
    return {row["id"]: (row["weight"] if row["weight"] else 1.0) for row in rows}


def _batch_source_credibilities(conn, source_ids):
    """Fetch source credibilities in bulk. Returns {source_id: credibility}."""
    if not source_ids:
        return {}
    placeholders = ",".join("?" for _ in source_ids)
    rows = conn.execute(
        f"""SELECT id, credibility_score, bayesian_alpha, bayesian_beta,
                   true_positives, false_positives
            FROM sources WHERE id IN ({placeholders})""",
        list(source_ids),
    ).fetchall()
    result = {}
    for row in rows:
        alpha = row["bayesian_alpha"] if row["bayesian_alpha"] else 2.0
        beta = row["bayesian_beta"] if row["bayesian_beta"] else 2.0
        if (row["true_positives"] or 0) == 0 and (row["false_positives"] or 0) == 0:
            result[row["id"]] = row["credibility_score"] if row["credibility_score"] else 0.5
        else:
            result[row["id"]] = round(alpha / (alpha + beta), 4)
    return result


def rescore_all_alerts(conn, frequency_snapshot=None):
    """
    Re-score all unreviewed alerts with current weights, Bayesian credibility,
    and Z-score frequency factors.

    Args:
        conn: Database connection
        frequency_snapshot: Optional pre-built {keyword_id: (factor, z_score)} dict.
            If None, a snapshot is built once at the start to avoid redundant
            per-alert frequency lookups (O(n) -> O(1) per alert).

    Returns count of alerts rescored.
    """
    alerts = conn.execute(
        """SELECT a.id, a.keyword_id, a.source_id, a.created_at, a.published_at
        FROM alerts a WHERE a.reviewed = 0"""
    ).fetchall()

    if frequency_snapshot is None:
        keyword_ids = list({alert["keyword_id"] for alert in alerts})
        frequency_snapshot = build_frequency_snapshot(conn, keyword_ids=keyword_ids)

    # Batch-fetch keyword weights and source credibilities to avoid N+1 queries
    all_keyword_ids = {alert["keyword_id"] for alert in alerts if alert["keyword_id"]}
    all_source_ids = {alert["source_id"] for alert in alerts if alert["source_id"]}
    weight_cache = _batch_keyword_weights(conn, all_keyword_ids)
    cred_cache = _batch_source_credibilities(conn, all_source_ids)

    # Import locally to avoid circular module initialization:
    # ep_scoring -> risk_scoring (score_to_severity) and this path needs ep_scoring.
    from analytics.ep_scoring import compute_operational_score

    count = 0
    for alert in alerts:
        score_args = frequency_snapshot.get(alert["keyword_id"])
        freq_override = score_args[0] if score_args else None
        z_override = score_args[1] if score_args else None

        keyword_weight = weight_cache.get(alert["keyword_id"], 1.0)
        source_credibility = cred_cache.get(alert["source_id"], 0.5)

        if freq_override is not None:
            frequency_factor = freq_override
            z_score = z_override if z_override is not None else 0.0
        else:
            frequency_factor, z_score = get_frequency_factor(conn, alert["keyword_id"])

        recency_factor, recency_hours = compute_recency_factor(
            published_at=alert["published_at"], created_at=alert["created_at"]
        )

        risk_score, severity = compute_risk_score(
            keyword_weight, source_credibility, frequency_factor, recency_hours
        )
        conn.execute(
            "UPDATE alerts SET risk_score = ?, severity = ? WHERE id = ?",
            (risk_score, severity, alert["id"]),
        )
        conn.execute(
            """INSERT INTO alert_scores
            (alert_id, keyword_weight, source_credibility, frequency_factor, z_score, recency_factor, final_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert["id"],
                keyword_weight,
                source_credibility,
                frequency_factor,
                z_score,
                recency_factor,
                risk_score,
            ),
        )
        compute_operational_score(conn, alert["id"])
        count += 1
    conn.commit()
    return count


def update_source_credibility_bayesian(conn, source_id, is_true_positive):
    """
    Update Bayesian credibility when an alert is classified as TP or FP.
    Uses Beta distribution: credibility = alpha / (alpha + beta).
    """
    if is_true_positive:
        conn.execute(
            """UPDATE sources SET
                true_positives = COALESCE(true_positives, 0) + 1,
                bayesian_alpha = COALESCE(bayesian_alpha, 2.0) + 1
            WHERE id = ?""",
            (source_id,),
        )
    else:
        conn.execute(
            """UPDATE sources SET
                false_positives = COALESCE(false_positives, 0) + 1,
                bayesian_beta = COALESCE(bayesian_beta, 2.0) + 1
            WHERE id = ?""",
            (source_id,),
        )
    # Sync the credibility_score column with Bayesian estimate
    row = conn.execute(
        "SELECT bayesian_alpha, bayesian_beta FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    if row:
        new_cred = row["bayesian_alpha"] / (row["bayesian_alpha"] + row["bayesian_beta"])
        conn.execute(
            "UPDATE sources SET credibility_score = ? WHERE id = ?",
            (round(new_cred, 4), source_id),
        )


def compute_evaluation_metrics(conn, source_id=None):
    """
    Compute precision, estimated recall, and F1 for each source.

    Precision = TP / (TP + FP)
    Estimated Recall = TP / (TP + FN_est)

    Note: FN is *estimated* as ``reviewed_count - TP - FP``, i.e. reviewed
    alerts that were not explicitly classified.  This is an approximation;
    analysts who review without classifying inflate FN and depress recall.
    Enforce TP/FP classification on every reviewed alert for accurate recall.
    """
    if source_id is not None:
        source = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        sources = [source] if source else []
    else:
        sources = conn.execute("SELECT * FROM sources").fetchall()

    results = []
    for src in sources:
        tp = src["true_positives"] or 0
        fp = src["false_positives"] or 0
        reviewed_count = conn.execute(
            "SELECT COUNT(*) as count FROM alerts WHERE source_id = ? AND reviewed = 1",
            (src["id"],),
        ).fetchone()["count"]

        fn = max(0, reviewed_count - (tp + fp))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        alpha = src["bayesian_alpha"] or 2.0
        beta = src["bayesian_beta"] or 2.0

        results.append(
            {
                "source_id": src["id"],
                "source_name": src["name"],
                "true_positives": tp,
                "false_positives": fp,
                "total_reviewed": reviewed_count,
                "precision": round(precision, 4),
                "recall_estimated": round(recall, 4),
                "f1_score": round(f1, 4),
                "bayesian_credibility": round(alpha / (alpha + beta), 4),
                "static_credibility": src["credibility_score"] or 0.5,
                "recall_note": "Estimated: FN = reviewed - TP - FP. Classify all reviewed alerts for accurate recall.",
            }
        )

    return results
