# SRIA LANL Feasibility Note v0.3

## Authentication Red-Team Validation, Learned Review-Queue Ranking, and v0.5.0 Offline Integration

**Author:** Maysam Bayg Muhammady
**Affiliation:** Independent Researcher, AWOS AI
**Dataset:** LANL Authentication Dataset / LANL Unified Host and Network Dataset
**Status:** Feasibility validation / research prototype
**Document version:** v0.3
**Date:** 2026

---

## Executive Summary

This note extends the earlier SRIA LANL feasibility work from host/network correlation into authentication-based lateral-movement detection.

The previous feasibility notes showed that SRIA-style staged governance could reduce large-scale LANL host/network telemetry into reviewable multi-signal episodes. In v0.1, the pipeline processed Day 90 and isolated 12 Tier 1 suspicious-port + suspicious-process episodes. In v0.2, the same strongest Tier 1 hosts from Day 90 reappeared on Day 60, showing cross-day recurrence across two independently processed sampled days.

This v0.3 note documents a different but related validation track: **SRIA RT**, an authentication-topology detector tested against LANL red-team authentication events.

The goal was not to detect malware signatures, process names, or static indicators. The goal was to test whether SRIA-style reconstruction integrity could identify lateral-movement structure from authentication behavior alone.

The central finding is:

```text
SRIA’s authentication feature engine produced meaningful lateral-movement signals,
but the hand-written SRIA score was not the best ranking layer.
```

After multiple blind detection iterations, checkpointed full-run processing, clean baseline comparison, leakage correction, learned model comparison, queue audit, and offline learned-ranker integration, the strongest current architecture is:

```text
SRIA authentication/topology feature engine
+
learned review-queue ranker
+
analyst-facing explanation metadata
```

The current best learned ranker is:

```text
rf_depth10_cw_none
```

In the v0.5.0 offline application step, this saved RF depth-10 model was applied to 73,546 existing v0.3.6 accepted authentication episodes without rescanning `auth.txt`. It reproduced the expected queue-ranking result:

```text
Top 100:
  28 positive episodes
  126 represented red-team events
  91.30% represented red-team recall

Top 500:
  31 positive episodes
  138 represented red-team events
  100.00% represented red-team recall
```

Important limitation:

```text
This is review-queue ranking over accepted candidate episodes.
It is not yet deployment precision over the full negative enterprise population.
```

---

## 1. Background

SRIA is based on the premise that operational systems do not act directly on reality. They act on reconstructed representations of reality.

In the LANL host/network track, this meant reconstructing suspicious activity from host events, network flows, process signals, account context, and correlation windows.

In the authentication track, this means reconstructing lateral-movement risk from authentication topology:

* source host
* destination host
* user identity
* first-time edges
* source fanout
* user fanout
* source-user fanout
* temporal clustering
* compact lateral bursts
* fanout velocity
* novelty and entropy shaping

The hypothesis was simple:

```text
Real lateral movement should leave graph-structural traces,
even when static indicators are unavailable.
```

SRIA RT tests that hypothesis.

---

## 2. Dataset and Validation Setup

The SRIA RT track used LANL authentication telemetry and the LANL red-team file for validation.

The validation discipline was intentionally constrained:

```text
redteam.txt was used only for sparse-window selection and post-hoc validation.
Detector scoring did not use red-team source, destination, or user labels.
```

This distinction matters.

The detector was allowed to process authentication behavior near red-team time windows for practical runtime reasons, but it was not allowed to score events using attacker identities, red-team destinations, or red-team labels.

The scoring path used only authentication-derived structure.

---

## 3. Early Result: Real but Broad Signal

The first meaningful breakthrough occurred around SRIA RT v0.2.9.

The detector began matching real red-team lateral-movement structure through authentication topology alone.

The strongest recurring signals were:

* first-time source-user-to-destination edges
* first-time user-to-destination edges
* first-time source-to-destination edges
* compact lateral bursts
* source fanout
* user fanout
* source-user fanout
* short temporal clustering

A representative matched pattern showed:

```text
source: C17693
user: U748@DOM1
signals:
  compact_lateral_burst
  first_time_source_to_dest
  first_time_source_user_to_dest
  first_time_user_to_dest
  source_fanout
  source_user_fanout
  user_fanout
```

This was important because the detector was not matching random overlap. It was converging toward structurally coherent lateral-movement behavior.

Several matches also had exact-start alignment:

```text
episode start_time == red-team event time
```

That was a strong indication that the detector had found a real behavioral surface.

However, the detector was still too broad.

The early authentication detector behaved like:

```text
a weak but real unsupervised lateral-movement sensor
```

It found meaningful structure, but produced too many candidate episodes for practical analyst review.

---

## 4. Manual Gate Iteration

The next phase attempted to improve the hand-scored detector through tighter shaping.

The main engineering changes included:

* entropy penalties for oversized enterprise fanout
* compactness rewards for short dense bursts
* temporal acceleration through fanout velocity
* stricter candidate gates
* near-match rescue logic
* observed-range recall reporting
* checkpointed long-run execution for the billion-line authentication file

Several versions were tested:

| Version | Role                                                |
| ------- | --------------------------------------------------- |
| v0.2.8  | Initial sparse-window blind authentication detector |
| v0.2.9  | Precision-shaped blind authentication detection     |
| v0.3.0  | Precision + velocity shaping                        |
| v0.3.1  | Tightened precision and observed-range validation   |
| v0.3.3  | Recall recovery + near-match rescue                 |
| v0.3.5  | Gate-pruned A/B calibration                         |
| v0.3.6  | Stateful checkpointed batch runner                  |

The checkpointed v0.3.6 runner was necessary because `auth.txt` contains more than one billion lines. Full or near-full processing on a laptop required resumable batches, persistent detector memory, and output streaming instead of holding all episodes in memory.

This produced an important operational improvement:

```text
SRIA RT could process the large authentication file safely in batches
while preserving first-time edge memory across invocations.
```

---

## 5. Full-Run Comparison: v0.3.3 vs v0.3.6

A key comparison was performed between v0.3.3 and v0.3.6.

v0.3.3 was more recall-heavy.
v0.3.6 was more precision-pruned.

The comparison showed:

```text
v0.3.3 unique matched red-team events: 260
v0.3.6 unique matched red-team events: 138
caught by both: 138
caught by v0.3.3 but lost by v0.3.6: 122
caught by v0.3.6 but not v0.3.3: 0
```

The lost v0.3.6 matches mostly came from:

```text
B_high_velocity
E_source_user_fanout_rescue
```

This showed that v0.3.6 was not discovering a better independent signal. It was mostly a stricter subset of v0.3.3.

That was a turning point.

The evidence suggested that further hand-tuning of gates was reaching diminishing returns.

---

## 6. Methodological Turning Point: Baselines

At this stage, the central question changed.

It was no longer:

```text
Can the hand gates be tuned better?
```

It became:

```text
Should the hand gates be the final ranking layer at all?
```

To answer this, baseline models were introduced.

The first baseline attempt revealed a methodological issue: learned models were initially allowed to see gate-derived outputs such as:

* SRIA score
* raw score
* entropy penalty
* max risk
* gate identity

That created leakage.

A learned model using the hand score as an input is not an independent comparison against the hand score.

So the baseline was corrected.

---

## 7. Clean Baseline Design

The clean baseline removed all gate-output leakage.

The learned models were not allowed to use:

```text
score
raw_score
legacy_sria_score
legacy_raw_score
entropy_penalty
max_risk
gate__*
candidate_gate_encoded
label
redteam_count
redteam_indices
exact_start_count
```

The learned models could use only upstream episode features such as:

```text
duration
events_count
destination_count
user_count
new_destination_event_count
first_time_event_count
first_time_signal_hits
novelty_ratio
compactness_score
fanout_velocity_score
peak_velocity_new_dests
signal indicators
```

This created a fairer test:

```text
Given the same engineered SRIA features,
does a learned model rank accepted episodes better than the hand SRIA score?
```

The answer was yes.

---

## 8. Learned Ranking Results

After leakage correction, learned models consistently outperformed the legacy hand score as a review-queue ranking layer.

The strongest current model is:

```text
rf_depth10_cw_none
```

On the v0.3.6 accepted-episode set, the RF depth-10 learned ranker produced:

```text
Top 20:
  12 positive episodes
  60 represented red-team events
  43.48% represented red-team recall

Top 50:
  20 positive episodes
  97 represented red-team events
  70.29% represented red-team recall

Top 100:
  28 positive episodes
  126 represented red-team events
  91.30% represented red-team recall

Top 500:
  31 positive episodes
  138 represented red-team events
  100.00% represented red-team recall
```

The legacy SRIA score, on the same accepted rows, performed poorly as a ranking layer.

It found no represented red-team events in the top 100, top 500, or top 1,000.

This is the clearest current result:

```text
The SRIA feature engine is valuable.
The hand SRIA score is weak.
The learned ranker is substantially better for analyst queue prioritization.
```

---

## 9. v0.5.0 Offline Learned-Ranker Integration

After v0.4.4 identified `rf_depth10_cw_none` as the strongest current review-queue model, the next step was to test whether the learned ranker could be applied as a clean offline integration layer.

This became SRIA RT v0.5.0.

The objective was intentionally narrow:

```text
Do not rescan auth.txt.
Do not change candidate generation.
Do not modify the detector.
Load the saved learned model.
Apply it to existing accepted episode JSONL.
Write ranked analyst queues and an audit report.
```

The v0.5.0 command loaded:

```text
model: v044_train_v033_score_v036\model_v033_rf_depth10_cw_none.joblib
episodes: v036_batches\episodes_v036_accepted.jsonl
matches: v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl
```

It then scored:

```text
73,546 accepted episodes
```

The model artifact included:

```text
model_name: rf_depth10_cw_none
train_branch: v033
score_branch: v036
version: v0.4.4
feature_count: 29
leakage_discipline: stripped_features_no_score_raw_entropy_maxrisk_gate_outputs
```

The v0.5.0 offline application reproduced the expected result:

```text
Top 100:
  positive_episodes: 28
  represented red-team events: 126
  represented red-team recall: 91.30%
  exact-start count: 23

Top 500:
  positive_episodes: 31
  represented red-team events: 138
  represented red-team recall: 100.00%
  exact-start count: 26

Top 1,000:
  positive_episodes: 31
  represented red-team events: 138
  represented red-team recall: 100.00%
  exact-start count: 26

Top 5,000:
  positive_episodes: 31
  represented red-team events: 138
  represented red-team recall: 100.00%
  exact-start count: 26
```

This matters because the learned ranker is no longer only an experimental comparison result.

It is now an applied offline integration layer:

```text
existing SRIA accepted episodes
→ saved RF model
→ ranked analyst queues
→ reproducible audit report
```

That is the practical bridge from v0.4 experimentation to v0.5 integration.

---

## 10. Current Architecture

The current SRIA RT direction is no longer a purely hand-gated detector.

The emerging architecture is:

```text
Layer 1:
  SRIA authentication/topology feature engine

Layer 2:
  learned review-queue ranker

Layer 3:
  analyst-facing explanation and governance metadata
```

The hand gates are not discarded. They remain useful as:

* candidate generators
* explanatory metadata
* diagnostic structure
* analyst context
* fallback logic
* interpretable signal grouping

But they should not remain the final ranking authority.

The ranking layer should be learned.

---

## 11. Interpretation

This result should not be framed as a failure of SRIA.

It is better understood as a maturation of SRIA.

The original SRIA hypothesis was not that hand-written thresholds would outperform all learned models. The stronger hypothesis was that SRIA-style reconstruction features could expose meaningful integrity failures in operational telemetry.

That hypothesis is still supported.

The features survived.

The hand score did not.

That distinction matters.

The system found useful structure in authentication topology, but the decision surface over that structure was better learned than manually weighted.

---

## 12. What This Confirms

| Finding                                                         | Status                                 |
| --------------------------------------------------------------- | -------------------------------------- |
| Authentication topology contains useful lateral-movement signal | Confirmed within this validation setup |
| First-time edge structure is a strong primitive                 | Confirmed                              |
| Compact burst + fanout convergence is meaningful                | Confirmed                              |
| Hand gates can generate useful candidate episodes               | Confirmed                              |
| Hand SRIA score is weak as final ranker                         | Confirmed                              |
| Leakage-stripped learned rankers improve queue ordering         | Confirmed                              |
| RF depth-10 is the current best review-queue model              | Confirmed so far                       |
| Offline learned-ranker application reproduces v0.4.4 results    | Confirmed in v0.5.0                    |

---

## 13. What Remains Unknown

| Question                                                                      | Status                               |
| ----------------------------------------------------------------------------- | ------------------------------------ |
| What is deployment precision across full negative enterprise background?      | Unknown                              |
| How many high-scoring false positives appear outside red-team sparse windows? | Unknown                              |
| How stable is RF depth-10 across broader training/scoring splits?             | Needs further testing                |
| Would graph neural networks or sequence models outperform this architecture?  | Likely possible, not yet tested here |
| Can the learned ranker be integrated into streaming mode safely?              | Future work                          |
| Can the same architecture generalize beyond LANL?                             | Unknown                              |

---

## 14. Limitations

1. **Review-queue ranking, not deployment precision**
   The strongest v0.4.4 and v0.5.0 results rank accepted candidate episodes. They do not yet measure full deployment precision across all enterprise background activity.

2. **Sparse-window evaluation constraint**
   The authentication validation used red-team time windows for feasible evaluation. Although scoring did not use red-team labels, broader negative-only evaluation remains necessary.

3. **Accepted-episode population only**
   The learned ranker improves ordering among accepted episodes. It does not yet replace the full candidate-generation process.

4. **LANL-specific validation**
   The result is based on LANL authentication data. External validation is required.

5. **Model interpretability tradeoff**
   RF depth-10 performs better than the simpler tree model, but it is less directly interpretable. The decision tree remains useful as an explanation baseline.

6. **Not full SRIA v3.0**
   This implementation focuses on authentication topology and lateral-movement reconstruction. It does not yet include the full semantic policy, delegation, approval provenance, or mission-context layers described in broader SRIA theory.

---

## 15. Immediate Next Step: v0.5.1

The v0.5.0 milestone applied the learned ranker offline to accepted episodes.

The next safe step is v0.5.1:

```text
deployment-style output mode
+
validation/debug separation
+
official analyst queue preservation
```

This means producing two versions of ranked outputs:

```text
Research/debug queue:
  includes validation fields such as redteam_count and redteam_indices

Deployment-style queue:
  excludes validation fields
  keeps only operational episode features, model score, and explanation metadata
```

This separation matters because red-team labels are useful for research validation but must not appear in a production-like analyst queue.

The next target should be:

```text
SRIA RT v0.5.1:
  create clean analyst-facing queue outputs
  preserve research/debug outputs separately
  document the distinction in the audit report
```

---

## 16. Future Work

### 16.1 Broader Negative Evaluation

The most important next validation step is to evaluate high-scoring learned-ranker episodes outside red-team sparse windows.

This should answer:

```text
What is the analyst burden in normal enterprise background?
How many high-scoring episodes appear per day?
How much review volume is required to maintain recall?
```

### 16.2 Cross-Branch and Cross-Time Stability

The model should be tested under additional splits:

* train v0.3.3 → score v0.3.6
* train v0.3.6 → score v0.3.3
* time-based splits
* red-team-group-based splits
* negative-only background sampling

### 16.3 Interpretable Explanation Layer

RF depth-10 should be paired with explanation metadata:

* top contributing features
* signal set
* candidate gate
* novelty metrics
* fanout metrics
* compactness metrics
* source/user/destination summary

This preserves the operational explainability that makes SRIA useful.

### 16.4 Stronger Baselines

Future comparison should include:

* tuned random forests
* gradient boosting
* graph-based lateral movement models
* sequence models
* temporal graph features
* host/user embedding approaches

### 16.5 Integration With Broader SRIA

The authentication-topology layer should eventually connect back to the broader SRIA framework:

* semantic integrity
* behavioral integrity
* identity continuity
* action governance
* policy-aware review
* proportional response recommendations

---

## 17. Conclusion

SRIA LANL v0.1 showed that SRIA-style staged governance could compress large-scale host/network telemetry into reviewable multi-signal episodes.

SRIA LANL v0.2 showed that the strongest Day 90 Tier 1 hosts reappeared on Day 60, suggesting cross-day recurrence across sampled days.

SRIA RT v0.3 now adds a new result:

```text
Authentication topology contains meaningful lateral-movement signal,
but the final ranking layer should be learned rather than hand-scored.
```

The most important outcome is not only the improved ranking metric. It is the methodological correction.

The project moved from hand tuning to baseline comparison, from gate confidence to leakage discipline, from detector scoring to analyst-queue evaluation, and now from model comparison to offline learned-ranker integration.

The current conclusion is restrained but meaningful:

```text
SRIA’s feature engine survived validation.
The hand score did not.
The learned ranker reproduced its queue performance in an offline integration layer.
```

This is a stronger direction than the original design.

The next milestone is v0.5.1: separating deployment-style analyst outputs from research/debug validation outputs, preserving interpretability, and preparing broader negative-background evaluation.

---

## 18. Current Artifact Status

| Artifact                                  | Status    |
| ----------------------------------------- | --------- |
| SRIA LANL Feasibility Note v0.1           | Complete  |
| SRIA LANL Feasibility Note v0.2           | Complete  |
| SRIA RT v0.3.3 full run                   | Complete  |
| SRIA RT v0.3.6 checkpointed run           | Complete  |
| v0.3.3 vs v0.3.6 comparison               | Complete  |
| v0.4.1 clean baseline                     | Complete  |
| v0.4.2 learned scorer export              | Complete  |
| v0.4.3 queue audit                        | Complete  |
| v0.4.4 model comparison                   | Complete  |
| RF depth-10 analyst queues                | Preserved |
| v0.5.0 offline learned-ranker application | Complete  |
| v0.5.1 deployment-style output separation | Next      |

---

**Status:** Research feasibility milestone
**Claim boundary:** Accepted-episode review-queue ranking, not deployment precision
**Current best model:** `rf_depth10_cw_none`
**Current architecture:** SRIA feature engine + learned ranker + explanation metadata
