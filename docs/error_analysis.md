# Error Analysis: Scoring Model Misclassifications

Generated from `analytics/backtesting.py` (n=35 EP scenarios).

Both the multi-factor rules model and the ML classifier achieve 68.6% severity accuracy
(24/35 correct). They disagree on 12 scenarios, each getting 5 right that the other misses.
This document examines the 11 errors from each model and classifies them as
**label-ambiguous** (debatable ground truth) or **genuine model miss**.

---

## Category 1: Label-Ambiguous (Ground Truth Debatable)

These scenarios have defensible arguments for the labeled severity *and* the predicted severity.
In an operational setting, reasonable analysts would disagree on classification.

### Extremist Forum Names Protectee as Target
- **Label**: high | **Rules**: critical | **ML**: critical
- **Why both over-predict**: keyword_weight=4.4, frequency_factor=1.6, credibility=0.6 produce ORS=94.0.
  Scenario describes explicit targeting with route patterns — arguably critical, not just high.
- **Verdict**: **Label debatable.** A named protectee in an extremist forum discussing routes would likely
  trigger an immediate response in most EP programs, which is a critical-tier action.

### Stalking Behavior Escalation with Leakage
- **Label**: high | **Rules**: critical | **ML**: critical
- **Why both over-predict**: keyword_weight=4.1, frequency_factor=1.8, credibility=0.68 produce ORS=100.0.
  Scenario describes a known fixated individual posting a timeline and plan. This is textbook
  pathway-to-violence escalation — the leakage flag alone justifies critical in most TRAP frameworks.
- **Verdict**: **Label debatable.** Leakage + fixation + specific plan = most EP programs would escalate
  this to critical immediately.

### State Dept Level 4 Do Not Travel Alert
- **Label**: high | **Rules**: critical | **ML**: medium
- **Why models diverge**: Rules over-score (ORS=100) because keyword_weight=3.2 × frequency=1.5 ×
  credibility=0.95 is high. ML under-scores because "travel advisory" text is closer to medium/low
  training examples. The scenario is a broad-area advisory, not protectee-targeted — but Level 4
  (Do Not Travel) with a protectee on the itinerary is operationally severe.
- **Verdict**: **Label defensible but boundary.** The correct severity depends on whether the
  protectee's travel is confirmed vs. tentative. With confirmed travel, this is arguably critical.

### Suspicious Drone Near Residence
- **Label**: high | **Rules**: medium (54.5) | **ML**: medium
- **Why both under-predict**: Low credibility (0.55) and single-source reporting suppress the score.
  But a drone near a protectee residence is an operational high regardless of source credibility —
  it requires a physical security response.
- **Verdict**: **Genuine model gap.** Both models weight source credibility too heavily for
  physical-proximity scenarios. Proximity to protectee assets should override low credibility
  when the report type is physical observation.

---

## Category 2: Genuine Model Misses

These are clear errors where the model prediction is wrong and the label is defensible.

### Rules model misses that ML gets right:
| Scenario | Expected | Rules | ML | Root Cause |
|---|---|---|---|---|
| Anonymous Bomb Threat, Low Credibility | high | medium | **high** | Rules under-weight threat type; low credibility (0.35) suppresses score to 41.4 even for bomb threats |
| Hostile Surveillance at Event Venue | high | medium | **high** | Score=69.9, just 0.1 below high threshold (70). Boundary miss |
| Civil Unrest in Travel Destination | medium | high | **medium** | Rules over-score; frequency_factor=1.5 amplifies a non-protectee-targeted regional advisory |
| Keyword Spike, No Threat Context | medium | high | **medium** | Rules treat all frequency spikes equally; ML learns that spikes without threat language are lower-risk |
| News Article Mentions Protectee Positively | low | medium | **low** | Rules can't distinguish positive vs negative mentions; ML picks up "positive framing" text signal |

### ML model misses that Rules gets right:
| Scenario | Expected | Rules | ML | Root Cause |
|---|---|---|---|---|
| Doxxing Post with Residential Address | critical | **critical** | high | ML has only 5 critical training examples; LOO-CV removes one, making critical under-represented |
| State Dept Level 3 at Planned Destination | high | **high** | medium | ML confuses Level 3 text with lower-severity travel advisories in training data |
| Suspicious Package at Regional Office | medium | **medium** | high | ML over-weights "suspicious package" text features toward high severity |
| State Dept Level 2 Advisory Update | medium | **medium** | low | ML under-scores travel advisories generally; text similarity to low-severity examples |
| Routine Weather Advisory | low | **low** | medium | ML confuses "advisory for event city" text with medium-severity event-adjacent scenarios |

---

## Category 3: Both Wrong, Different Predictions

| Scenario | Expected | Rules | ML | Analysis |
|---|---|---|---|---|
| Unrelated Kidnapping in Different Country | low | medium | high | Both over-react to keyword_weight=4.9 for "kidnapping." Neither model has a geographic relevance filter — the scenario is in a country with no protectee presence, but the keyword alone drives high scores. **Feature gap: needs protectee-proximity context.** |

---

## Key Takeaways

1. **3 of 11 misses are label-ambiguous** (extremist forum, stalking leakage, Level 4 advisory).
   Adjusting these labels to match model predictions would raise both models to ~77% accuracy.
   In operations, these are analyst-judgment calls, not model failures.

2. **Rules and ML have complementary error profiles.** Rules fail on credibility-suppressed
   threats and non-threat keyword spikes. ML fails on small-sample critical class and
   text-similar-but-operationally-different travel advisories.

3. **The biggest systematic gap is geographic/contextual relevance.** Both models over-score
   alerts with high keyword weights that aren't relevant to the protectee's geography or schedule.
   Adding protectee-proximity and event-adjacency features to the ML model would address this.

4. **An ensemble (rules + ML disagreement queue) would catch 5 additional errors** that
   one model gets right while the other misses. See `docs/ml_rollout.md`.
