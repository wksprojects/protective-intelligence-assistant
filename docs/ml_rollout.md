# ML Production Rollout: Shadow Scoring & Disagreement Workflow

## Context

The rules-based ORS model and the ML classifier (TF-IDF + LR) achieve identical aggregate
metrics on the initial benchmark (68.6% accuracy, 0.867 escalation precision) but make
different errors on 12/35 scenarios. This document defines how to run both models in
parallel and use analyst adjudication to improve both over time.

---

## Phase 1: Shadow Scoring (Week 1-4)

**Goal**: Run ML predictions alongside rules without changing operational behavior.

### Implementation

1. **Dual-score every alert** at ingestion time:
   - `ors_score` (existing) — rules-based, drives severity and triage.
   - `ml_severity` (new column on `alerts`) — ML prediction, logged but not surfaced to analysts.

2. **Log disagreements** to a new `model_disagreements` table:
   ```sql
   CREATE TABLE model_disagreements (
       id INTEGER PRIMARY KEY,
       alert_id INTEGER REFERENCES alerts(id),
       rules_severity TEXT,
       ml_severity TEXT,
       rules_score REAL,
       analyst_verdict TEXT DEFAULT NULL,  -- filled by adjudication
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```

3. **Dashboard addition**: Admin tab shows disagreement rate (% of alerts where models disagree)
   and a running accuracy comparison once analyst verdicts accumulate.

### Success Criteria
- Shadow scoring adds < 50ms latency per alert.
- Disagreement rate stabilizes (expect 15-30% initially).
- No disruption to existing triage workflow.

---

## Phase 2: Disagreement Queue (Week 4-8)

**Goal**: Surface disagreements to analysts for adjudication to build labeled training data.

### Workflow

1. When `rules_severity != ml_severity`, alert is flagged with a **disagreement indicator**
   in the Alert Triage tab (distinct icon or badge).

2. Analyst reviews the alert normally and classifies (TP/FP + disposition). Their severity
   judgment is recorded as `analyst_verdict` in `model_disagreements`.

3. Weekly batch: compare analyst verdicts to both model predictions. Track:
   - Rules accuracy on disagreements
   - ML accuracy on disagreements
   - Which model the analyst agrees with more often

### Expected Outcome
- Builds a labeled dataset of ~50-200 real adjudicated alerts per month.
- Identifies systematic model gaps (e.g., rules under-score low-credibility bomb threats,
  ML over-score geographic-irrelevant high-weight keywords).

---

## Phase 3: Retraining & Promotion (Week 8+)

**Goal**: Retrain ML model on analyst-adjudicated data and promote to production if it outperforms rules.

### Retraining Pipeline

1. **Training data**: Combine golden benchmark (n=35) + analyst-adjudicated disagreements +
   TP/FP classifications from `dispositions` table.

2. **Feature expansion**: Add protectee-proximity and event-adjacency features that the
   text-only ML model currently lacks (identified in error analysis as the biggest gap).

3. **Evaluation**: Hold out 20% of adjudicated data. Compare:
   - Rules accuracy on holdout
   - Retrained ML accuracy on holdout
   - Ensemble (rules + ML majority vote) accuracy on holdout

4. **Promotion criteria** (all must hold on holdout set):
   - ML escalation precision >= rules escalation precision
   - ML escalation recall >= rules escalation recall
   - ML false positive count <= rules false positive count
   - n_holdout >= 50 adjudicated alerts

### Promotion Options
- **Replace**: ML becomes primary scorer (if clearly superior).
- **Ensemble**: Use ML as primary, flag rules-disagree alerts for review (if comparable).
- **Assist**: Keep rules as primary, surface ML-disagrees as "second opinion" (conservative).

---

## Architecture Impact

| Component | Change | Effort |
|---|---|---|
| `alerts` table | Add `ml_severity TEXT` column | Migration, low |
| `model_disagreements` table | New table | Schema addition, low |
| `analytics/ep_pipeline.py` | Call `ml_classifier.predict()` after rules scoring | ~20 LOC |
| Dashboard Alert Triage | Disagreement badge on flagged alerts | UI change, medium |
| Dashboard Admin tab | Disagreement rate chart + accuracy comparison | New chart, medium |
| `scripts/retrain_ml.py` | Batch retrain from adjudicated data | New script, medium |
| `make retrain` | Makefile target for retraining | One line |

**Total estimated effort**: 2-3 days of implementation for Phase 1-2.
Phase 3 depends on accumulating sufficient adjudicated data (~2 months of operations).

---

## Risk Mitigation

- **ML never auto-escalates** in Phase 1-2. It only flags disagreements for human review.
- **Analyst workload**: Disagreement queue adds ~15-30% more review items, but these are
  precisely the alerts most likely to be misclassified — highest-value analyst attention.
- **Model drift**: Retrain monthly with expanding adjudicated dataset. Track accuracy
  on golden benchmark as regression guard (must not degrade below 65%).
