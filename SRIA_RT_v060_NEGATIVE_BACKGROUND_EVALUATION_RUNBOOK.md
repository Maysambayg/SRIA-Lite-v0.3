# SRIA RT v0.6.0 Negative-Background Evaluation Runbook

**Version:** v0.6.0  
**Status:** Draft runbook  
**Scope:** Negative-background characterization for SRIA RT v0.5 pipeline  
**Primary objective:** Measure queue volume, score distribution, concentration, analyst burden, and false-positive pressure when the current SRIA RT v0.5 system is exposed to broader non-red-team enterprise background windows.

---

## 1. Purpose

SRIA RT v0.5 established an accepted-episode review-queue pipeline under sparse LANL red-team-window validation. It produced deployment-style queues, measured analyst burden, rejected hard source caps, packaged repeated-source activity into source clusters, clarified official recall semantics, and generated analyst-facing packets.

The remaining evaluation gap is negative-background characterization:

> What happens when SRIA RT is run outside sparse red-team-centered windows?

This runbook defines the first disciplined evaluation step. It does not attempt to prove deployment readiness. It measures how the existing v0.5 system behaves under broader background conditions.

---

## 2. Core Evaluation Boundary

For v0.6, the system must be tested as-is.

Do **not** change:

- SRIA feature logic
- Candidate-generation gates
- Learned ranker model
- Score thresholds
- Deployment queue format
- Analyst packet format
- Official metric definitions
- Source-cluster packaging rules

Do **not** retrain the model during the first negative-background pass.

The goal is not optimization. The goal is characterization.

---

## 3. Current System Under Test

The system under test is the current SRIA RT v0.5 chain:

```text
SRIA candidate / accepted episode generation
→ current primary learned ranker: RF depth-10
→ deployment / research output separation
→ burden measurement
→ source-cluster analyst packaging
→ debug annotation semantics
→ analyst cluster packet
```

The v0.5 validation boundary remains:

```text
accepted-episode review-queue ranking under sparse LANL red-team-window validation
```

The v0.6 task is to test behavior outside that boundary.

---

## 4. Questions v0.6 Must Answer

The first negative-background evaluation should answer:

1. How many accepted episodes does SRIA RT generate outside red-team-centered windows?
2. What does the learned-ranker score distribution look like over background windows?
3. Are Top 100 / Top 500 / Top 1000 queues still analyst-usable?
4. Are queues dominated by benign enterprise structures such as machine accounts, service-account-like behavior, recurring administrative sources, or domain-controller-like patterns?
5. What source/user concentration appears in background-only queues?
6. Do source-cluster packets remain readable under background load?
7. Does the current ranker produce manageable background queues, or does it inflate into high-volume noise?

---

## 5. Required Measurements

Each negative-background run should record:

- Background windows selected
- Red-team exclusion margin
- Distance from nearest red-team event
- Estimated or actual auth lines scanned
- Candidate events processed
- Accepted episodes generated
- Ranked queue sizes
- Score distribution
- Top-score tail behavior
- Episodes per hour
- Source concentration
- User concentration
- Machine-account / service-account-like concentration
- Dominant gates
- Dominant signals
- Top 100 / Top 500 / Top 1000 burden metrics
- Repeated-source clusters
- Analyst packet readability

If validation labels are absent, do not report precision/recall. Report background burden and queue characteristics only.

---

## 6. Window Selection Policy

Window selection must be auditable.

Each selected background window must include:

- `window_id`
- `start_time`
- `end_time`
- `duration`
- `selection_reason`
- `distance_from_nearest_redteam_event`
- `estimated_auth_line_count`, if available
- `redteam_exclusion_margin`
- `status`

Selected windows should be outside known red-team neighborhoods. The first pass should use windows that are far enough from red-team activity to characterize ordinary enterprise background.

---

## 7. Exclusion Policy

Known red-team event neighborhoods must be excluded before background windows are selected.

The exclusion margin should be explicit and recorded. A default starting point is:

```text
±3600 seconds around each known red-team event
```

This margin can be widened later, but the first run must record the margin used.

---

## 8. Proposed Evaluation Sequence

```text
v0.6.0  Negative-background evaluation runbook
v0.6.1  Auditable background-window selection
v0.6.2  SRIA candidate generation on selected background windows
v0.6.3  Apply current RF depth-10 learned ranker
v0.6.4  Generate v0.5-style deployment/research queues
v0.6.5  Burden / concentration / score distribution analysis
v0.6.6  Analyst packet generation
v0.6.7  Negative-background evaluation report
```

---

## 9. Tiered Evaluation Plan

### Tier A — Smoke Background Characterization

Purpose: verify runtime, file shape, and output behavior.

Suggested scope:

- 3 to 5 background windows
- Moderate duration
- Far from red-team neighborhoods
- No retraining
- No threshold changes

Success condition:

```text
The pipeline runs end-to-end and produces measurable queue/burden outputs.
```

### Tier B — Medium Background Characterization

Purpose: evaluate broader background behavior across multiple time regions.

Suggested scope:

- More windows
- Wider temporal spread
- Same current ranker
- Same output chain

Success condition:

```text
Score distribution, queue volume, concentration, and analyst packet readability can be characterized across background windows.
```

### Tier C — Broad Background Pass

Purpose: later larger-scale characterization after Tier A and Tier B are clean.

Do not start here.

---

## 10. Interpretation Rules

A high-volume background result does not invalidate SRIA RT. It may mean:

```text
the feature engine is sensitive but needs background calibration or suppression logic
```

A low-volume clean result does not prove deployment readiness. It means:

```text
the sampled background windows did not produce severe queue inflation
```

A useful v0.6 result is one that characterizes the failure mode or stability profile honestly.

---

## 11. What Must Not Be Claimed Yet

Until negative-background evaluation is complete, do not claim:

- Full deployment precision
- Enterprise-ready false-positive rate
- Generalized production readiness
- Robustness across arbitrary enterprise background
- Incident declaration capability
- Complete lateral-movement detection

The correct claim remains:

```text
SRIA RT currently demonstrates a high-recall accepted-episode review queue and analyst-readable source-cluster packaging under sparse LANL red-team-window validation.
```

---

## 12. Recommended Immediate Next Step

Run:

```text
sria_rt_v061_select_background_windows.py
```

Expected outputs:

```text
v061_background_windows_manifest.json
v061_background_windows.csv
v061_excluded_redteam_neighborhoods.csv
```

These files should define an auditable set of non-red-team background windows for Tier A / Tier B characterization.

---

## 13. Completion Criteria for v0.6.0

v0.6.0 is complete when:

- The negative-background evaluation boundary is documented.
- The no-retraining / no-feature-change discipline is explicit.
- Window selection requirements are defined.
- Required measurements are listed.
- Interpretation rules prevent overclaiming.
- v0.6.1 has a clear implementation target.

