# SRIA RT System Card v0.1.1

**System name:** SRIA RT — Semantic Reconstruction Integrity Architecture for authentication topology review  
**Version covered:** SRIA RT v0.5 branch through v0.5.5b  
**Status:** Research prototype / analyst-output validation branch  
**Author:** Maysam Bayg Muhammady  
**Date:** 2026-06-23

---

## 1. Purpose

SRIA RT is a research prototype for ranking and packaging suspicious authentication-topology episodes for analyst review. It is designed to surface structural authentication patterns associated with lateral movement, especially patterns involving first-time source-user-destination relationships, source/user fanout, compact bursts, and propagation-style behavior.

The current system does not claim autonomous detection or production-ready deployment. Its validated role is review-queue generation and analyst-facing packaging over accepted SRIA authentication episodes.

---

## 2. Current Capability

The current v0.5 branch supports the following workflow:

```text
accepted SRIA authentication episodes
→ learned-ranker scoring
→ deployment/research output separation
→ analyst burden measurement
→ source-diversity policy testing
→ source-cluster analyst packaging
→ debug annotation diagnostic
→ analyst-facing cluster packet
```

The system produces ranked queues and analyst-readable source clusters. The strongest current output is the analyst cluster packet, which groups repeated-source activity while preserving the original learned-ranker order.

---

## 3. Data Used

The current validation work uses LANL authentication telemetry and LANL red-team authentication events. The v0.5 branch operates over previously generated accepted v036 SRIA authentication episodes rather than rescanning `auth.txt` during the analyst-output stages.

Important scope limitation:

```text
Current metrics are accepted-episode review-queue ranking metrics under sparse red-team-window validation.
They are not full deployment precision metrics over the complete enterprise background population.
```

---

## 4. Model / Ranking Method

The v0.5 branch uses an offline learned ranker trained on SRIA authentication/topology features. The current primary learned ranker is an RF depth-10 model artifact:

```text
model_v033_rf_depth10_cw_none.joblib
```

The learned ranker scores accepted SRIA episodes using leakage-stripped topology features. The later v0.5.1–v0.5.5b stages do not retrain, rescore, rerank, or mutate queues; they separate outputs, measure burden, test policies, package clusters, and clarify reporting metrics.

---

## 5. Key Signals / Features

The system is centered on authentication-topology signals, including:

- first-time source-user-destination edges
- first-time source-destination edges
- first-time user-destination edges
- source fanout
- user fanout
- source-user fanout
- compact lateral bursts
- fanout velocity
- propagation convergence
- novelty ratio
- entropy/oversize shaping terms

A known feature dependency in the current branch is that `first_time_source_user_to_dest` dominates the accepted episode population. This is expected for the current validation branch, but it should be tested under broader background conditions.

---

## 6. Validated Metrics So Far

The strongest current validation result is the v0.5.1/v0.5.5b ranked review queue over accepted v036 episodes:

```text
Top 100:
  positive episodes: 28
  official unique represented red-team events: 126 / 138
  official represented recall: 91.30%

Top 500:
  positive episodes: 31
  official unique represented red-team events: 138 / 138
  official represented recall: 100.00%

Top 1000:
  positive episodes: 31
  official unique represented red-team events: 138 / 138
  official represented recall: 100.00%

Top 5000:
  positive episodes: 31
  official unique represented red-team events: 138 / 138
  official represented recall: 100.00%
```

Metric definition:

```text
Official represented recall = deduplicated union of represented red-team event indices across the selected queue.
```

Annotation totals such as per-episode `redteam_count` or v0.5.4 cluster `debug_rt_events` are analyst/debug context only and may double-count represented events.

---

## 7. Analyst Output

The v0.5.5b analyst packet summarizes the ranked queue as source clusters. For example:

```text
Top 100:
  100 episodes
  72 source clusters
  largest cluster: C17693, 28 episodes
  official represented recall: 91.30%

Top 500:
  500 episodes
  435 source clusters
  largest cluster: C17693, 31 episodes
  official represented recall: 100.00%
```

The C17693 cluster is presented as a structured activity bundle, including episode count, rank span, time span, unique users, dominant gates, top signals, and representative episodes with explanations.

The analyst packet is intended to prioritize review, not to declare incidents. This output is intended to support analyst review, not automated suppression or autonomous incident declaration.

---

## 8. Policy Findings

A hard per-source cap policy was tested in v0.5.3 and rejected as the default queue policy.

Reason: source caps increased diversity but destroyed too much validated signal. Even a cap of 20 episodes per source retained only 91 / 138 represented red-team events, or 65.94% represented recall, compared with the uncapped Top 500 result of 138 / 138.

Interpretation:

```text
C17693 concentration is not merely queue collapse. It carries validated signal.
```

Preferred policy:

```text
Preserve uncapped learned-ranker order.
Use source-cluster packaging as the analyst readability layer.
```

---

## 9. What Should Not Be Claimed Yet

The current SRIA RT branch should not yet be described as:

- production-ready intrusion detection
- validated deployment precision over full enterprise background
- autonomous malicious-authentication classification
- a complete lateral-movement detector
- a replacement for existing SIEM/EDR investigation workflows
- validated across multiple organizations or datasets

The correct claim is narrower:

```text
SRIA RT currently demonstrates a high-recall accepted-episode review queue and analyst-readable source-cluster packaging under sparse LANL red-team-window validation.
```

---

## 10. Known Limitations

1. **Sparse-window validation:** Current metrics are measured over accepted episodes and sparse red-team-centered windows, not full enterprise background.
2. **Precision uncertainty:** Deployment precision over the complete negative population remains unmeasured.
3. **Feature-population dependency:** The current queue strongly depends on first-time source-user-destination novelty.
4. **Single-dataset validation:** The current evidence is based on LANL authentication telemetry and LANL red-team events.
5. **Accepted-episode boundary:** Later v0.5 stages operate over accepted SRIA episodes; they do not evaluate missed candidates outside that accepted population.
6. **Analyst interpretation required:** The output is an analyst-review interface, not an autonomous decision system.

---

## 11. Next Required Evaluation

The most important remaining evaluation is negative-background testing:

```text
What happens outside sparse red-team windows?
```

A serious external presentation should include at least one measurement of queue behavior over broader non-red-team enterprise background, including:

- volume of high-scoring episodes outside red-team windows
- analyst burden under realistic background conditions
- false-positive concentration by source/user/gate
- stability of learned-ranker scores under broader background
- recall/precision tradeoff under a deployment-like population

---

## 12. Recommended External Framing

SRIA RT should be presented as a research-engineering prototype for authentication-topology review, not as a finished security product.

Suggested one-sentence description:

```text
SRIA RT is a prototype authentication-topology ranking and analyst-packaging system that uses SRIA-derived structural features and a learned ranker to generate high-recall review queues for lateral-movement-style authentication behavior.
```

Suggested methodological claim:

```text
In accepted-episode sparse-window validation on LANL authentication data, the current RF depth-10 queue captured 126/138 represented red-team events in the Top 100 and 138/138 in the Top 500, while v0.5.5b converted the queue into analyst-readable source-cluster packets without changing the ranking.
```

Suggested limitation statement:

```text
These results do not yet establish production precision over full enterprise background traffic; that is the next required evaluation step.
```

---

## 13. Current Status

```text
v0.5.0  offline learned-ranker application              complete
v0.5.1  deployment/research output separation            complete
v0.5.2  deployment burden measurement                    complete
v0.5.3  hard source-cap policy test                      complete; hard caps rejected
v0.5.4  source-cluster analyst packaging                 complete
v0.5.5  debug annotation diagnostic                      complete
v0.5.5b analyst cluster packet                           complete
```

The next recommended milestone is full-background negative evaluation before broader external claims.

Recommended next experiment:

```text
Run the same v0.5.1-v0.5.5b output chain over broader non-red-team background windows to measure queue volume, concentration, and false-positive burden.
```

