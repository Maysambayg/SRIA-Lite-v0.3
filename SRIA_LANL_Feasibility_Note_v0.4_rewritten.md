# SRIA LANL Feasibility Note v0.4

## Negative-Background Evaluation, Empirical Score/Feature Geometry, Tail Stratification, and Tail Triage Policy Simulation

**Author:** Maysam Bayg Muhammady  
**Affiliation:** Independent Researcher, AWOS AI  
**Dataset:** LANL Authentication Dataset / LANL Unified Host and Network Dataset  
**Status:** Feasibility validation / research prototype  
**Document version:** v0.4 rewritten  
**Date:** 2026  

---

## Plain-Language Abstract

This is a research note about a system that reconstructs behavioral episodes from enterprise authentication logs and ranks them for analyst review. The system was tested against public Los Alamos National Laboratory cybersecurity datasets. In the current phase, known redteam-associated authentication episodes were placed deep in the upper tail of a sampled background score distribution under the same learned ranker. The high-score tail was not structurally uniform: rare background top-tail episodes were mostly fanout/rescue-like, while known redteam-associated episodes were mostly compact/propagation-like. A final triage simulation showed that analyst presentation order can be improved by using a balanced subtype-aware queue without retraining the model or suppressing any episode category.

---

## Executive Summary

This note extends the SRIA LANL feasibility series beyond positive redteam sparse-window validation into broader negative-background pressure testing, empirical score/feature geometry analysis, tail stratification, and analyst triage policy simulation.

The earlier notes established three milestones.

In v0.1, SRIA-style staged governance processed Day 90 of the LANL Unified Host and Network Dataset and reduced 173M host/network events into a small set of reviewable multi-signal episodes.

In v0.2, the strongest Day 90 Tier 1 hosts reappeared on Day 60, showing that the pattern was not limited to a single sampled day.

In v0.3, the project moved into the LANL authentication dataset. SRIA RT showed that authentication topology contains meaningful lateral-movement signal, but that the hand-written SRIA score was not the best final ranking layer. The strongest architecture became:

```text
SRIA authentication/topology feature engine
+
leakage-stripped learned review-queue ranker
+
analyst-facing explanation metadata
```

The current best learned ranker remains:

```text
rf_depth10_cw_none
```

The key limitation at the end of v0.3 was clear:

```text
The learned ranker worked well on accepted redteam-window candidate episodes,
but deployment pressure over broader negative enterprise background had not yet been measured.
```

This v0.4 note documents what happened after that.

The project moved through:

```text
v0.5.1  deployment-style output separation
v0.5.2  analyst burden measurement
v0.5.3  source-cap policy test
v0.5.4–v0.5.5b source-cluster analyst packaging
v0.6.1–v0.6.4 negative-background evaluation
v1.2.1–v1.2.4 empirical score/feature geometry and tail stratification
v1.2.5  tail triage policy simulation
```

The central v0.4 finding is:

```text
SRIA's learned ranker does not simply produce an unmanageable flood of high-risk background episodes.
Across sampled Tier B background windows, the score distribution is highly compressed, source concentration is controlled, and the high-score tail is structurally heterogeneous.
```

The strongest result is not merely that redteam-associated episodes score high.

The stronger result is:

```text
Known redteam-associated episodes occupy the extreme upper region of the accepted-background score distribution under the same learned ranker, but their structure differs from the rarest background top-100 tail.
```

The rarest background top-100 tail is mostly:

```text
fanout/rescue-heavy empirical score/feature geometry
```

The redteam-associated same-score tail is mostly:

```text
compact/propagation-heavy empirical score/feature geometry
```

The final v1.2.5 triage simulation then tested whether this structure can improve analyst presentation order without changing the detector, ranker, gates, features, or episode population.

The best overall policy was:

```text
70% compact/propagation
20% mixed
10% fanout/rescue
```

This balanced policy recovered:

```text
Top 100:   21 / 31 redteam-associated episodes = 67.74%
Top 250:   27 / 31 redteam-associated episodes = 87.10%
Top 500:   30 / 31 redteam-associated episodes = 96.77%
Top 1,000: 31 / 31 redteam-associated episodes = 100.00%
```

It also reduced the rank depth required to recover all redteam-associated accepted episodes from:

```text
1,384 under pure score-only ranking
```

to:

```text
534 under balanced subtype-aware triage
```

This is the main practical advance of v0.4.

SRIA RT should not be framed primarily as a detector or ranker. It is better described as:

```text
an authentication episode reconstruction system
+
a leakage-stripped learned review-queue ranker
+
analyst-facing explanation and source-cluster packaging
+
an empirical score/feature geometry analysis layer
+
a subtype-aware analyst presentation policy layer
```

Important limitation:

```text
This is still feasibility validation.
It is not production precision.
It is not proof of intrinsic authentication manifolds.
It does not classify background tail episodes as benign or malicious.
It does not claim that compact/propagation structure is always malicious.
It does not claim that fanout/rescue structure is benign.
```

---

## 1. Background: Where v0.3 Ended

SRIA LANL Feasibility Note v0.3 concluded that authentication topology contains useful lateral-movement signal.

The strongest redteam validation result came from applying the saved RF depth-10 model to 73,546 accepted v0.3.6 authentication episodes.

The offline learned-ranker application reproduced:

```text
Top 100:
  28 positive episodes
  126 represented redteam events
  91.30% represented redteam recall

Top 500:
  31 positive episodes
  138 represented redteam events
  100.00% represented redteam recall
```

The conclusion was restrained:

```text
SRIA's feature engine survived validation.
The hand score did not.
The learned ranker became the correct review-queue layer.
```

But the open question was not solved:

```text
What happens when the same system is exposed to broader non-redteam background?
```

That question became the v0.4 work.

---

## 2. v0.5.1: Deployment-Style Output Separation

The first step after v0.3 was not new modeling.

It was output discipline.

SRIA RT v0.5.1 separated:

```text
research/debug outputs
```

from:

```text
deployment-style analyst queues
```

This mattered because redteam validation fields are useful for research, but they must not appear in a production-like analyst queue.

The v0.5.1 principle was:

```text
The model may be validated with redteam labels,
but the deployment queue must not contain those labels.
```

This created two clean output modes:

```text
Research/debug queue:
  includes validation fields such as redteam_count and redteam_indices

Deployment-style queue:
  excludes validation fields
  preserves only operational episode fields, model score, and explanation metadata
```

This was a governance improvement, not a model improvement.

It made the pipeline cleaner and closer to operational discipline.

---

## 3. v0.5.2: Analyst Burden Measurement

The next question was practical:

```text
If we give analysts the learned-ranked queue,
does it collapse onto one source or one user?
```

The answer was no.

The clean deployment queues showed broad source and user diversity.

Selected results:

```text
Top 100:
  rows: 100
  unique sources: 72
  unique users: 91
  top source share: 28.00%
  top 5 sources share: 33.00%

Top 500:
  rows: 500
  unique sources: 435
  unique users: 466
  top source share: 6.20%
  top 5 sources share: 9.60%

Top 1,000:
  rows: 1,000
  unique sources: 860
  unique users: 943
  top source share: 3.10%
  top 5 sources share: 6.60%

Top 5,000:
  rows: 5,000
  unique sources: 3,775
  unique users: 4,382
  top source share: 0.84%
  top 5 sources share: 4.02%
```

Interpretation:

```text
The queue is analyst-usable.
It is not a single-source collapse.
```

This mattered because a high-recall queue that only points to one dominant source would be operationally weak.

Instead, the learned ranker produced a broad review surface.

---

## 4. v0.5.3: Source-Cap Policy Test

The next policy question was whether hard per-source caps should be used.

This is a common analyst-queue temptation:

```text
Limit each source to N entries so the queue looks more diverse.
```

SRIA tested this directly using the v0.5.1 research/debug ranked queue with a 138 represented-redteam-event denominator.

The result was clear:

```text
Hard per-source caps reduce represented redteam recall.
```

Selected source-cap results:

| Queue | Cap | Rows | Represented redteam recall | Unique sources | C17693 share |
|---:|---:|---:|---:|---:|---:|
| Top 100 | 3 | 100 | 15.94% | 95 | 3.00% |
| Top 100 | 5 | 100 | 21.74% | 93 | 5.00% |
| Top 100 | 10 | 100 | 39.13% | 88 | 10.00% |
| Top 100 | 20 | 100 | 65.94% | 79 | 20.00% |
| Top 500 | 3 | 500 | 15.94% | 468 | 0.60% |
| Top 500 | 5 | 500 | 21.74% | 460 | 1.00% |
| Top 500 | 10 | 500 | 39.13% | 455 | 2.00% |
| Top 500 | 20 | 500 | 65.94% | 445 | 4.00% |
| Top 1,000 | 3 | 1,000 | 15.94% | 920 | 0.30% |
| Top 1,000 | 5 | 1,000 | 21.74% | 898 | 0.50% |
| Top 1,000 | 10 | 1,000 | 39.13% | 876 | 1.00% |
| Top 1,000 | 20 | 1,000 | 65.94% | 867 | 2.00% |

The conclusion:

```text
Reject hard source caps as the default policy.
```

Source diversity should be handled through presentation and clustering, not by deleting high-ranked episodes from the queue.

This preserved signal while still allowing analysts to view clustered source context.

---

## 5. v0.5.4–v0.5.5b: Source-Cluster Analyst Packaging

After rejecting hard caps, SRIA moved to reporting-only source clustering.

This produced analyst context without changing the ranking.

The distinction is important:

```text
Ranking remains uncapped.
Cluster reporting summarizes concentration.
No ranked episode is removed.
```

The system produced source-cluster reports for Top 100, Top 500, Top 1,000, and Top 5,000 queues.

A later diagnostic step clarified a key accounting issue:

```text
Official recall must be computed from deduplicated redteam event union.
Cluster debug counts are annotation totals and may double-count.
```

This prevented inflated interpretation of cluster-level summaries.

The final v0.5.5b analyst packaging result was accepted:

```text
Top 100:
  clusters: 72
  largest cluster: C17693 with 28 episodes
  official represented recall: 91.30%

Top 500:
  clusters: 435
  largest cluster: C17693 with 31 episodes
  official represented recall: 100.00%

Top 1,000:
  clusters: 860
  largest cluster: C17693 with 31 episodes
  official represented recall: 100.00%

Top 5,000:
  clusters: 3,775
  largest cluster: C2057 with 42 episodes
  official represented recall: 100.00%
```

Interpretation:

```text
The analyst queue can remain uncapped while still being explainable through source-cluster packaging.
```

---

## 6. System Card: Claim Boundary

Before broader negative-background evaluation, the project locked a system-card boundary.

The safe claim became:

```text
SRIA RT currently provides high-recall accepted-episode review-queue ranking
under sparse LANL redteam-window validation, with analyst-readable source-cluster packaging.
```

The prohibited claim became:

```text
SRIA RT is production-ready intrusion detection.
```

The system card explicitly rejected:

```text
91–100% detection precision
full enterprise false-positive rate established
autonomous intrusion confirmation
calibrated probability of compromise
```

This discipline matters because the v0.3 result was strong, but it was still accepted-episode queue ranking.

The next phase had to test background pressure.

---

## 7. v0.6 Negative-Background Evaluation

The v0.6 track was designed to answer:

```text
What happens when the current system is applied to broader non-redteam background?
```

The rules were strict:

```text
No retraining
No gate changes
No feature changes
No threshold tuning
No redteam validation during scoring
No auth.txt rescan beyond required extraction stages
```

This was a pressure test of the current v0.5 system as-is.

---

## 8. v0.6.1a: Auth-Time Profiler

A full direct background selector over the billion-line `auth.txt` was too heavy.

So SRIA first built a compact time-profile scan.

The profiler processed:

```text
1,051,430,459 auth lines
```

with:

```text
bad lines: 0
auth time range: 1 to 5,011,199
bucket count: 1,392
elapsed seconds: 2,405.63
lines per second: 437,070
```

This created a compact profile for selecting background windows without repeatedly scanning the full authentication file.

---

## 9. v0.6.1b: Tier B Background Window Selection

Using the compact profile, SRIA selected nine Tier B background windows distributed across early, middle, and late portions of the dataset.

The selected windows were outside the redteam exclusion neighborhoods and targeted comparable density bands.

Tier B windows:

```text
early:
  bg_001, bg_002, bg_003

middle:
  bg_004, bg_005, bg_006

late:
  bg_007, bg_008, bg_009
```

This created a sampled negative-background substrate for pressure testing.

Important caveat:

```text
Tier B is a sampled background evaluation, not a full-enterprise deployment run.
```

---

## 10. v0.6.2: Background Window Extraction

The extraction step pulled the selected Tier B windows from `auth.txt`.

Results:

```text
scanned lines: 887,539,406
matched lines: 7,185,941
bad lines: 0
stop reason: past_last_window_end
elapsed seconds: 2,008.96
lines per second: 441,790
```

All extracted window counts matched the profile estimates exactly.

This made the Tier B background set authoritative for the v0.6 test:

```text
Tier B background input:
  7,185,941 authentication lines
```

---

## 11. v0.6.3: Background Episode Generation

The v0.6.3 generator processed the nine Tier B windows independently using the existing SRIA detector logic.

Boundary:

```text
No model loading
No learned ranking
No retraining
No redteam validation
No auth.txt full scan
```

Results:

```text
windows processed: 9
raw lines read: 7,185,941
parsed success events: 7,083,499
bad lines: 0
accepted episodes: 105,866
suppressed episodes: 926,054
finalized episodes: 1,031,920
elapsed seconds: 266.91
raw lines per second: 26,923
```

Per-window accepted episode counts:

```text
bg_001:  9,774
bg_002: 10,735
bg_003: 10,340
bg_004: 12,060
bg_005: 11,742
bg_006: 12,216
bg_007: 13,343
bg_008: 12,853
bg_009: 12,803
```

Interpretation:

```text
The feature engine is sensitive.
The candidate generator produces many accepted structural episodes in dense background windows.
The learned ranker is necessary to determine how much of this survives into analyst review.
```

Important caveat:

```text
v0.6.3 used window-local independent generation.
It did not carry pre-window/global first-time memory into each background window.
This may inflate novelty in background windows.
```

That caveat must remain attached to v0.6 background findings.

---

## 12. v0.6.4: Learned Ranker Applied to Background Episodes

v0.6.4 applied the current primary learned ranker unchanged to the 105,866 accepted Tier B background episodes.

Boundary:

```text
No retraining
No feature changes
No gate changes
No redteam validation
No auth.txt scan
```

Run summary:

```text
windows scored: 9
accepted background episodes scored: 105,866
feature count: 29
elapsed seconds: 57.72
```

Aggregate score and burden summary:

```text
score max: 0.448932
score p99: 0.016345
score p95: 0.003135
score p90: 0.001094
score p50: 0.000046

severity background: 105,853
severity low_review: 13
severity medium_review: 0
severity high_review: 0
severity critical_review: 0

unique sources: 11,905
unique users: 19,701
top source: C105 at 0.56%
top 5 sources share: 2.61%
```

This was the first real negative-background pressure result.

Interpretation:

```text
The learned ranker compresses most accepted background episodes into a very low-score floor.
The high-score tail exists, but it is sparse.
There is no source collapse.
There is no broad medium/high/critical background flood under the current severity thresholds.
```

This substantially improves the confidence boundary relative to v0.3.

---

## 13. Why the v0.6.4 Result Matters

At the end of v0.3, the concern was:

```text
Maybe the learned ranker only works inside redteam sparse windows.
Maybe broader background will produce too many high-scoring false positives.
```

v0.6.4 did not prove production precision, but it answered part of that concern.

In the sampled Tier B background:

```text
105,866 accepted background episodes
only 13 low_review episodes
0 medium/high/critical episodes
top source share only 0.56%
top 5 source share only 2.61%
```

This suggests:

```text
The learned ranker is not simply firing broadly on accepted background structure.
```

It also revealed a new question:

```text
What is the empirical score/feature geometry of the high-score tail?
```

That became the v1.2 measurement layer.

---

## 14. v1.2.1: Geometry Measurement and Interpretation

SRIA v1.2 converted the v0.6.4 ranked background output into empirical score-regime diagnostics.

It partitioned the 105,866 accepted background episodes into:

```text
R2 = top 100
R1 = ranks 101–5,000
R0 = ranks > 5,000
```

Counts:

```text
R0: 100,866
R1: 4,900
R2: 100
```

Boundary/separation metrics:

```text
R0_R1 Wasserstein: 0.01164
R1_R2 Wasserstein: 0.13517
R0_R2 Wasserstein: 0.14682
```

Curvature proxy:

```text
R0 mean_abs_curvature: 1.76e-08
R1 mean_abs_curvature: 6.15e-06
R2 mean_abs_curvature: 1.22e-03
```

Interpretation:

```text
R0 = flat background floor
R1 = transition shelf
R2 = high-curvature tail
```

Controlled finding:

```text
SRIA RT v0.6.4 ranked background output induces measurable rank-induced empirical score-regime structure under v1.2 diagnostics.
```

Important boundary:

```text
This does not prove intrinsic authentication manifolds.
It shows measurable rank-induced score-regime structure in the current output.
```

---

## 15. v1.2.2: Redteam Contrast Geometry

v1.2.2 compared rare background R2 episodes against known redteam-associated v036 accepted episodes in observed Φ-space.

Counts:

```text
background R2: 100
redteam-associated: 31
common Φ features: 31
```

Redteam association was recovered cleanly:

```text
method: episode_id_match
matched count: 31
accepted id column: id
match id count: 31
```

Main contrast:

```text
standardized centroid distance: 3.9395
mean featurewise Wasserstein: 9.5367
```

Feature differences showed a clear pattern.

Background R2 was more:

```text
source-user fanout rescue heavy
entropy-soft-duration heavy
longer duration
higher novelty ratio
higher first-time signal volume
```

Redteam-associated episodes were more:

```text
compact
temporally dense
user-fanout active
propagation-convergent
compact-lateral-burst active
```

Controlled finding:

```text
Known redteam-associated v036 episodes are distinguishable from rare Tier B background R2 episodes in observed Φ-space.
```

Important caveat:

```text
v1.2.2 was a Φ-space comparison.
The score comparison was not yet fully calibrated because background R2 and v036 redteam JSONL carried different score semantics.
```

That led to v1.2.3.

---

## 16. v1.2.3: Same-Score Redteam Contrast

v1.2.3 applied the same learned RF depth-10 ranker to the 31 redteam-associated v036 accepted episodes.

This solved the score-calibration problem.

Counts:

```text
background all: 105,866
background R2: 100
redteam-associated: 31
model features: 29
```

Same-score result:

```text
redteam median background percentile: 99.8933
redteam minimum background percentile: 98.7220
redteam maximum background percentile: 99.9915
```

Threshold placement:

```text
background top 100 threshold:
  redteam above threshold: 15 / 31
  share: 48.39%

background top 500 threshold:
  redteam above threshold: 29 / 31
  share: 93.55%

background top 1,000 threshold:
  redteam above threshold: 30 / 31
  share: 96.77%

background top 5,000 threshold:
  redteam above threshold: 31 / 31
  share: 100.00%
```

Interpretation:

```text
Every redteam-associated episode scored above the background top-5,000 threshold.
Almost all scored above the background top-500/top-1,000 thresholds.
Nearly half scored inside the background top-100 threshold.
```

This was the strongest same-score result up to that point.

But it was not a simple "redteam always outranks background R2" story.

Background R2 mean score:

```text
0.1470
```

Redteam-associated same-score mean:

```text
0.1110
```

So redteam-associated episodes were lower on average than the absolute top-100 background tail, but still far above the general background distribution.

Controlled finding:

```text
Under same-score evaluation, known redteam-associated v036 episodes occupy the extreme upper region of the accepted-background score distribution, while remaining structurally distinguishable from the rarest background R2 episodes.
```

This suggested that the high tail is not homogeneous.

That became v1.2.4.

---

## 17. v1.2.4: Tail Stratification

v1.2.4 tested whether the high-score tail splits into structural subtypes.

Inputs:

```text
background ranked queue:
  top 5,000 background tail

redteam same-score output:
  31 redteam-associated accepted episodes scored under the same learned ranker
```

The module defined post-hoc diagnostic strata:

```text
fanout/rescue tail
compact/propagation tail
mixed tail
```

Boundary:

```text
These are diagnostic strata.
They are not new detection labels.
They are not production classifications.
```

Counts:

```text
background tail: 5,000
background R2: 100
background R1 tail: 4,900
redteam-associated: 31
combined: 5,031
```

Subtype composition:

```text
background R2:
  fanout/rescue tail: 83%
  compact/propagation tail: 0%
  mixed tail: 17%

redteam-associated:
  compact/propagation tail: 67.74%
  fanout/rescue tail: 22.58%
  mixed tail: 9.68%

background R1 tail:
  compact/propagation tail: 36.90%
  fanout/rescue tail: 29.06%
  mixed tail: 34.04%
```

The strongest contrast:

```text
compact/propagation tail:
  redteam share: 67.74%
  background R2 share: 0.00%

fanout/rescue tail:
  redteam share: 22.58%
  background R2 share: 83.00%
```

Interpretation:

```text
The high-score tail is structurally heterogeneous.
The rarest background top-100 tail is mostly fanout/rescue empirical score/feature geometry.
The redteam-associated same-score tail is mostly compact/propagation empirical score/feature geometry.
```

This set up the final policy question:

```text
Can subtype-aware presentation order improve analyst efficiency without suppressing any high-tail structure?
```

---

## 18. v1.2.5: Tail Triage Policy Simulation

v1.2.5 tested whether the subtype structure discovered in v1.2.4 can improve analyst presentation order.

The simulation used:

```text
v1_2_4_tail_stratification_results\tail_stratification_assignments.csv
```

Input population:

```text
total rows: 5,031
background rows: 5,000
redteam-associated evaluation rows: 31
```

Boundary:

```text
No model loading
No retraining
No feature changes
No gate changes
No auth.txt scan
No new detection logic
Policies change presentation order only
No episode suppression
Redteam labels used only for evaluation
```

The policies tested were:

```text
A_score_only:
  pure score descending

B_compact_first:
  compact/propagation first, then mixed, then fanout/rescue;
  score descending within subtype

C_balanced_70_20_10:
  70 compact/propagation, 20 mixed, 10 fanout/rescue proportional interleave

D_compact_mixed_then_extreme_rescue:
  compact first, mixed second, extreme fanout/rescue above override threshold third,
  remaining fanout/rescue after that

E_two_lane_compact_plus_rescue:
  two-lane interleave:
  two compact-or-mixed rows, then one fanout/rescue row
```

The decisive comparison:

```text
Top 100 recall:
  A_score_only:            15 / 31 = 48.39%
  B_compact_first:         20 / 31 = 64.52%
  C_balanced_70_20_10:     21 / 31 = 67.74%
  D_compact_mixed_extreme: 20 / 31 = 64.52%
  E_two_lane:              22 / 31 = 70.97%

Top 250 recall:
  A_score_only:            24 / 31 = 77.42%
  B_compact_first:         20 / 31 = 64.52%
  C_balanced_70_20_10:     27 / 31 = 87.10%
  D_compact_mixed_extreme: 20 / 31 = 64.52%
  E_two_lane:              28 / 31 = 90.32%

Top 500 recall:
  A_score_only:            28 / 31 = 90.32%
  B_compact_first:         21 / 31 = 67.74%
  C_balanced_70_20_10:     30 / 31 = 96.77%
  D_compact_mixed_extreme: 21 / 31 = 67.74%
  E_two_lane:              30 / 31 = 96.77%

Top 1,000 recall:
  A_score_only:            30 / 31 = 96.77%
  B_compact_first:         21 / 31 = 67.74%
  C_balanced_70_20_10:     31 / 31 = 100.00%
  D_compact_mixed_extreme: 21 / 31 = 67.74%
  E_two_lane:              30 / 31 = 96.77%
```

Policy C had the best overall redteam rank profile:

```text
C_balanced_70_20_10:
  first redteam rank: 1
  median redteam rank: 33
  p75 redteam rank: 131.5
  p90 redteam rank: 260
  last redteam rank: 534
  mean redteam rank: 99.32
```

Pure score-only ranking produced:

```text
A_score_only:
  first redteam rank: 10
  median redteam rank: 129
  p75 redteam rank: 225.5
  p90 redteam rank: 396
  last redteam rank: 1,384
  mean redteam rank: 196.35
```

Interpretation:

```text
Subtype-aware presentation improves early redteam-associated recovery, but compact-only ordering is too aggressive.
```

Compact-first policies captured compact/propagation redteam episodes early but delayed fanout/rescue and mixed redteam-associated episodes too far into the queue.

That is why B and D stalled:

```text
B_compact_first:
  Top 100: 20 / 31
  Top 500: 21 / 31
  Top 1,000: 21 / 31
```

The v1.2.5 conclusion:

```text
The best current analyst presentation policy is not pure score-only ranking and not compact-only ordering.
The best overall tested policy is balanced subtype-aware triage:
70% compact/propagation, 20% mixed, 10% fanout/rescue.
```

This policy improves early redteam-associated recovery while preserving fanout/rescue visibility.

Important caveat:

```text
This is triage optimization, not detection improvement.
No episodes are removed.
No subtype is declared benign or malicious.
```

---

## 19. Current Architecture After v0.4

The current SRIA RT architecture is now better understood as:

```text
Layer 1:
  authentication episode reconstruction engine

Layer 2:
  leakage-stripped learned review-queue ranker

Layer 3:
  deployment-style analyst queue

Layer 4:
  source-cluster explanation and concentration reporting

Layer 5:
  empirical score/feature geometry and tail subtype analysis

Layer 6:
  subtype-aware analyst presentation policy simulation
```

The system is not only producing a ranked queue.

It is now producing:

```text
accepted episodes
learned scores
review priorities
source/user concentration summaries
background score-regime diagnostics
redteam/background contrast geometry
tail subtype stratification
subtype-aware triage policy comparisons
```

This is a meaningful maturation from v0.3.

---

## 20. What v0.4 Confirms

| Finding | Status |
|---|---|
| Deployment-style queue separation is necessary and implemented | Confirmed |
| Learned-ranked queues are not single-source collapsed | Confirmed in v0.5.2 |
| Hard per-source caps damage recall and should not be default | Confirmed in v0.5.3 |
| Source clustering should be reporting-only, not rank-altering | Confirmed |
| Tier B background extraction and episode generation are feasible | Confirmed |
| Current learned ranker compresses most accepted background into low scores | Confirmed in v0.6.4 |
| No medium/high/critical flood appeared in Tier B background under current thresholds | Confirmed |
| Background score output has measurable rank-induced regime-like structure | Supported |
| Redteam-associated episodes are distinguishable from rare background R2 in Φ-space | Supported |
| Same learned ranker places redteam-associated episodes deep in the upper background tail | Supported |
| High-score tail is structurally heterogeneous | Confirmed |
| Background R2 is mostly fanout/rescue empirical score/feature geometry | Supported |
| Redteam-associated tail is mostly compact/propagation empirical score/feature geometry | Supported |
| Compact-only triage is too narrow and delays mixed/fanout redteam-associated rows | Confirmed |
| Balanced subtype-aware triage improves early redteam-associated recovery | Confirmed in v1.2.5 |
| v1.2.5 changes presentation order only; it does not change detection or ranking | Confirmed |

---

## 21. What Remains Unknown

| Question | Status |
|---|---|
| What is production precision across the full enterprise background? | Unknown |
| Does Tier B generalize to other background samples? | Unknown |
| How much does window-local novelty inflate background episodes? | Needs testing |
| Are compact/propagation tail episodes mostly malicious, redteam, benign admin activity, or mixed? | Unknown |
| Are fanout/rescue background R2 episodes benign, automation, misconfiguration, unknown adversarial activity, or mixed? | Unknown |
| Does subtype-aware triage generalize beyond the 31 accepted redteam-associated episodes? | Needs testing |
| Would retraining with subtype-aware features improve performance? | Not tested |
| Does this generalize beyond LANL? | Unknown |
| Are these true intrinsic manifolds or empirical score-regime structures? | Not proven |

---

## 22. Limitations

1. **Tier B background is sampled, not full deployment**  
   The negative-background evaluation used nine selected background windows. It is broader than sparse redteam validation but still not full enterprise deployment.

2. **Window-local generation caveat**  
   The v0.6.3 background generation was window-local independent. It did not include full pre-window global first-time memory. This may inflate novelty in background windows.

3. **Accepted episodes only**  
   The learned ranker operates over accepted episodes. The full raw authentication stream is not directly scored event-by-event.

4. **Redteam-associated subset is small**  
   The redteam-associated same-score contrast and triage evaluation used 31 accepted v036 episodes.

5. **Background R2 is not known benign**  
   Rare background R2 episodes are background-window episodes, not verified benign events.

6. **Tail subtypes are post-hoc diagnostics**  
   Fanout/rescue, compact/propagation, and mixed strata are diagnostic summaries, not model labels or production decisions.

7. **Subtype-aware triage is presentation-order optimization**  
   v1.2.5 does not improve the detector or retrain the ranker. It changes analyst presentation order only.

8. **Learned score is not calibrated probability**  
   A score of 0.10 or 0.30 is a ranking score, not a probability of compromise.

9. **No production false-positive rate**  
   v0.4 improves burden understanding and background pressure testing but does not establish deployment precision.

10. **Intrinsic manifold structure is not established**  
    In this note, "intrinsic manifold" would require stronger evidence than rank-induced score/feature separation. A reasonable evidentiary bar would include consistent Φ-space clustering across multiple independent background samples and independent datasets under matched feature construction, stable neighborhood structure under perturbation, and persistence of the same redteam/background subgeometry without relying on the same rank partition. The current result supports empirical score/feature geometry, not intrinsic authentication manifolds.

11. **LANL-specific validation**  
    The findings are based on LANL authentication data. External datasets are required for generalization.

12. **Not full SRIA v3.0**  
    This implementation focuses on authentication topology, episode reconstruction, learned ranking, review-queue governance, empirical tail stratification, and analyst presentation policy. It does not yet implement the full semantic policy, delegation, approval provenance, mission-context, or response-governance layers of broader SRIA theory.

---

## 23. Interpretation

The v0.4 result should not be framed as:

```text
SRIA detects attacks with 100% precision.
```

That would be wrong.

It should be framed as:

```text
SRIA reconstructs authentication episodes whose learned ranking surface places known redteam-associated episodes deep in the upper accepted-background tail, while empirical score/feature analysis shows that the high-score region is structurally heterogeneous and can support improved analyst presentation order.
```

The most important conceptual shift is:

```text
high score is not one kind of event.
```

There are at least two high-tail structures:

```text
1. fanout/rescue-heavy rare background structures
2. compact/propagation-heavy redteam-associated structures
```

v1.2.5 adds a practical policy result:

```text
compact/propagation should be prioritized,
but fanout/rescue must remain visible.
```

The best tested policy was therefore not compact-only ordering.

It was:

```text
70% compact/propagation
20% mixed
10% fanout/rescue
```

This means the system is no longer only ranking. It is beginning to expose useful structure inside the ranked tail and to support analyst queue design.

---

## 24. Immediate Next Step After v0.4

The v0.4 arc is now complete.

The next step should not be model tuning.

The next step should be robustness and uncertainty analysis around the v1.2.5 result.

Recommended next milestone:

```text
v1.2.6 Bootstrap and Robustness Analysis
```

Purpose:

```text
Estimate uncertainty around subtype enrichment and triage-policy improvement.
```

Recommended measurements:

```text
bootstrap confidence intervals for redteam recovery by depth
bootstrap confidence intervals for subtype enrichment
sensitivity to triage proportions, e.g. 60/30/10, 70/20/10, 80/10/10
sensitivity to the compact/mixed/fanout subtype margin
stability across additional background samples
```

The v1.2.5 result should be treated as promising but small-sample.

---

## 25. Future Work

### 25.1 Background Expansion

Run the same v0.6 process on additional background windows.

Goals:

```text
measure stability of background score floor
measure recurrence of fanout/rescue tail
measure recurrence of compact/propagation tail
test whether Tier B was representative
```

### 25.2 Global-Memory Background Generation

Repeat selected background runs with global pre-window memory.

Goal:

```text
measure how much window-local first-time novelty inflates accepted background episodes
```

### 25.3 Tail Triage Robustness

Extend v1.2.5 beyond a single fixed 70/20/10 policy.

Compare:

```text
score-only ranking
compact/propagation-first ranking
balanced 60/30/10
balanced 70/20/10
balanced 80/10/10
two-lane compact/mixed + fanout/rescue policies
fanout/rescue-aware clustering
```

Metrics:

```text
redteam-associated recovery by review depth
background review burden
source/user diversity
subtype composition per queue depth
confidence intervals under bootstrap resampling
```

### 25.4 Confidence Intervals and Bootstrap Stability

Because the redteam-associated subset is small, future work should include bootstrap uncertainty.

Metrics:

```text
confidence interval for subtype enrichment
confidence interval for same-score percentile placement
confidence interval for centroid distances
confidence interval for review-depth reduction under subtype-aware triage
```

### 25.5 External Validation

Test the same architecture on other enterprise authentication datasets if available.

Goal:

```text
determine whether compact/propagation redteam-like empirical score/feature geometry generalizes beyond LANL
```

### 25.6 Broader SRIA Integration

Future versions should connect authentication topology back to full SRIA governance:

```text
semantic integrity
identity continuity
behavioral integrity
policy-aware review
analyst decision provenance
proportional response recommendations
```

---

## 26. Conclusion

SRIA LANL v0.1 demonstrated that host/network telemetry could be reduced into reviewable multi-signal episodes.

SRIA LANL v0.2 showed recurrence of the strongest host/network Tier 1 patterns across sampled days.

SRIA LANL v0.3 showed that authentication topology contains meaningful lateral-movement signal, but that the final review-queue ranking layer should be learned rather than hand-scored.

SRIA LANL v0.4 now adds the missing negative-background, empirical score/feature geometry, tail stratification, and analyst presentation-policy layers.

The current findings are:

```text
1. The learned ranker compresses most accepted background episodes into a low-score floor.
2. The Tier B background queue is not source-collapsed.
3. Hard source caps harm recall and should not be default.
4. Known redteam-associated episodes score deep in the upper accepted-background tail under the same learned ranker.
5. The high-score tail is structurally heterogeneous.
6. Rare background R2 is mostly fanout/rescue empirical score/feature geometry.
7. Redteam-associated same-score episodes are mostly compact/propagation empirical score/feature geometry.
8. Compact-only triage is too narrow.
9. Balanced subtype-aware triage improves early redteam-associated recovery without removing fanout/rescue visibility.
```

The current conclusion is restrained but stronger than before:

```text
SRIA RT has moved from accepted-episode redteam ranking into sampled negative-background pressure testing, empirical tail stratification, and subtype-aware analyst triage simulation.
```

The best current description is:

```text
SRIA is an authentication episode reconstruction and review-queue geometry system with subtype-aware analyst presentation.
```

It is not yet a production detector.

It is not yet a calibrated compromise probability engine.

But it is no longer merely a hand-built heuristic pipeline.

It now has:

```text
validated feature primitives
a leakage-stripped learned ranker
deployment-style queue separation
source-cluster analyst packaging
sampled background burden measurement
same-score redteam contrast
tail subtype stratification
tail triage policy simulation
```

That is a meaningful feasibility milestone.

---

## 27. Current Artifact Status

| Artifact | Status |
|---|---|
| SRIA LANL Feasibility Note v0.1 | Complete |
| SRIA LANL Feasibility Note v0.2 | Complete |
| SRIA LANL Feasibility Note v0.3 | Complete |
| v0.5.1 deployment-style output separation | Complete |
| v0.5.2 burden measurement | Complete |
| v0.5.3 source-cap policy test | Complete |
| v0.5.4 source-cluster packaging | Complete |
| v0.5.5 official recall vs annotation diagnostic | Complete |
| v0.5.5b analyst cluster report | Complete |
| SRIA RT System Card v0.1.1 | Complete |
| v0.6.1a auth-time profiler | Complete |
| v0.6.1b background selector | Complete |
| v0.6.2 background extraction | Complete |
| v0.6.3 background episode generation | Complete |
| v0.6.4 learned ranker on background | Complete |
| v1.2.1 geometry interpretation | Complete |
| v1.2.2 redteam contrast geometry | Complete |
| v1.2.3 same-score redteam contrast | Complete |
| v1.2.4 tail stratification | Complete |
| v1.2.5 tail triage policy simulation | Complete |
| v1.2.6 bootstrap and robustness analysis | Proposed next |

---

## 28. References

A. D. Kent, "Cybersecurity Data Sources for Dynamic Network Research,"  
in *Dynamic Networks in Cybersecurity*, 2015.

```text
@InProceedings{akent-2015-enterprise-data,
   author = {Alexander D. Kent},
   title = {{Cybersecurity Data Sources for Dynamic Network Research}},
   year = 2015,
   booktitle = {Dynamic Networks in Cybersecurity},
   month = jun,
   publisher = {Imperial College Press}
}
```

A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events,"  
Los Alamos National Laboratory, http://dx.doi.org/10.17021/1179829, 2015.

```text
@Misc{kent-2015-cyberdata1,
  author = {Alexander D. Kent},
  title = {{Comprehensive, Multi-Source Cyber-Security Events}},
  year = {2015},
  howpublished = {Los Alamos National Laboratory},
  doi = {10.17021/1179829}
}
```

---

**Status:** Research feasibility milestone  
**Claim boundary:** sampled background pressure testing, same-score redteam contrast, and presentation-policy simulation; not production precision  
**Current best model:** `rf_depth10_cw_none`  
**Current architecture:** SRIA episode reconstruction engine + learned ranker + explanation metadata + empirical tail stratification + subtype-aware analyst presentation  
**Next milestone:** v1.2.6 Bootstrap and Robustness Analysis  
