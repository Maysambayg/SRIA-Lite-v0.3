# SRIA Unified Host/Network Day-02 v0.1.3a

## Clean Publication-Ready Triage Interpretation Report

**Status:** No-label feasibility and reconstruction interpretation.

**Scope:** LANL Unified Host and Network Day-02 host/network telemetry.

**Claim boundary:** This report describes review-queue reconstruction and triage presentation only. It does not claim attack confirmation, production precision, calibrated probability, recall, precision, or F1.

---

## 1. Executive Summary

SRIA Unified Day-02 reconstructed host-window episodes from LANL Unified Host and Network telemetry and converted the resulting ranked queue into cluster-aware analyst review views. The run processed 115,949,436 netflow rows and 64,844,144 Windows log rows, reconstructed 342,569 host-window keys, and wrote a 10,000-row ranked review queue.

The original score-ranked queue surfaced coherent cross-signal activity, but the top of the queue was locally concentrated. In the original Top 100, there were 58 unique hosts; the top host accounted for 15.00%, the top 5 hosts accounted for 38.00%, and the top 10 hosts accounted for 50.00%.

v0.1.2 improved analyst presentation without deleting or suppressing any episode. The cluster-aware Top 100 increased distinct host coverage to 98 unique hosts and reduced top-host share to 2.00%. The round-robin Top 100 reached 100 unique hosts with a 1.00% top-host share; the round-robin Top 500 reached 500 unique hosts.

Correct interpretation: SRIA Day-02 demonstrates scalable no-label host/network reconstruction, coherent cross-signal queueing, and presentation-layer burden reduction. It does not demonstrate confirmed attack detection.

---

## 2. Raw Processing Scale

```text
netflow lines processed:      115,949,436
netflow bad lines:            0
netflow host-src rows:        112,232,380
netflow host-dst rows:        101,319,472
netflow time range:           118,781-172,799
netflow elapsed seconds:      1591.32

WLS lines processed:          64,844,144
WLS bad JSON rows:            0
WLS missing-host rows:        0
WLS time range:               86,400-172,799
WLS elapsed seconds:          684.14
```

The pipeline streamed both large Day-02 files without parse failure. This supports the feasibility of the host/network reconstruction path at Day-02 scale.

---

## 3. Episode Reconstruction

```text
host-window keys total:       342,569
ranked rows written:          10,000
unique hosts in ranked queue: 4,622
score max:                    14.00
score mean:                   7.76
```

The output is a ranked analyst review queue. It is not a labeled detection verdict.

---

## 4. Original Queue Concentration

The original score-ranked queue was not globally collapsed, but the first analyst view was locally concentrated.

| top_k | unique_hosts | top_host | top_host_share | top_5_host_share | top_10_host_share | score_min | score_median | score_max | overlap_share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 58 | Comp916004 | 15.00% | 38.00% | 50.00% | 10.70 | 11.12 | 14.00 | 100.00% |
| 500 | 348 | Comp479002 | 3.00% | 12.20% | 19.20% | 9.70 | 10.20 | 14.00 | 100.00% |
| 1,000 | 683 | Comp303229 | 1.50% | 7.40% | 11.80% | 9.05 | 9.70 | 14.00 | 100.00% |
| 5,000 | 2,833 | Comp479002 | 0.30% | 1.50% | 3.00% | 7.45 | 8.20 | 14.00 | 100.00% |
| 10,000 | 4,622 | Comp916004 | 0.24% | 0.94% | 1.69% | 6.75 | 7.45 | 14.00 | 99.58% |

---

## 5. Cluster-Aware Improvement

The cluster-aware view reduces repeated-host saturation while preserving the original ranking as a reference artifact.

| top_k | unique_hosts | top_host | top_host_share | top_5_host_share | top_10_host_share | score_min | score_median | score_max | overlap_share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 98 | Comp137959 | 2.00% | 7.00% | 12.00% | 10.20 | 10.70 | 11.90 | 100.00% |
| 500 | 360 | Comp479002 | 3.00% | 10.80% | 17.40% | 9.70 | 10.20 | 12.30 | 100.00% |
| 1,000 | 691 | Comp479002 | 1.50% | 7.00% | 11.20% | 7.10 | 9.70 | 14.00 | 99.90% |
| 5,000 | 2,821 | Comp916004 | 0.48% | 1.86% | 3.36% | 7.10 | 8.20 | 14.00 | 99.34% |
| 10,000 | 4,622 | EnterpriseAppServer | 0.24% | 0.94% | 1.69% | 6.75 | 7.45 | 14.00 | 99.58% |

---

## 6. Round-Robin Improvement

The round-robin queue provides the cleanest first-pass analyst sweep by maximizing distinct host coverage at shallow review depth.

| top_k | unique_hosts | top_host | top_host_share | top_5_host_share | top_10_host_share | score_min | score_median | score_max | overlap_share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 100 | Comp916004 | 1.00% | 5.00% | 10.00% | 10.70 | 10.70 | 14.00 | 100.00% |
| 500 | 500 | Comp384041 | 0.20% | 1.00% | 2.00% | 9.40 | 10.00 | 14.00 | 100.00% |
| 1,000 | 1,000 | Comp383851 | 0.10% | 0.50% | 1.00% | 8.70 | 9.40 | 14.00 | 100.00% |
| 5,000 | 4,622 | Comp335066 | 0.04% | 0.20% | 0.40% | 6.75 | 7.75 | 14.00 | 99.96% |
| 10,000 | 4,622 | Comp916004 | 0.24% | 0.94% | 1.69% | 6.75 | 7.45 | 14.00 | 99.58% |

---

## 7. Top Persistent and Recurrent Clusters

Persistent and recurrent high-signal hosts are retained as investigation clusters rather than suppressed.

| cluster_rank_by_best_original_rank | host | queue_count | window_count | best_rank | score_max | presentation_class |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Comp916004 | 24 | 24 | 1 | 14.00 | persistent_cross_signal_infrastructure_like_cluster |
| 2 | Comp169810 | 8 | 8 | 16 | 12.30 | recurring_candidate_cluster |
| 3 | Comp908480 | 11 | 11 | 17 | 12.30 | recurrent_cross_signal_cluster |
| 4 | Comp395501 | 8 | 8 | 18 | 12.30 | recurring_candidate_cluster |
| 5 | Comp670762 | 4 | 4 | 19 | 11.90 | recurring_candidate_cluster |
| 6 | Comp137959 | 3 | 3 | 20 | 11.90 | recurring_candidate_cluster |
| 7 | Comp303229 | 15 | 15 | 21 | 11.80 | recurrent_cross_signal_cluster |
| 8 | Comp337732 | 15 | 15 | 23 | 11.80 | recurrent_cross_signal_cluster |
| 9 | Comp411120 | 5 | 5 | 24 | 11.70 | recurring_candidate_cluster |
| 10 | Comp974312 | 15 | 15 | 25 | 11.70 | recurrent_cross_signal_cluster |
| 11 | Comp704126 | 15 | 15 | 26 | 11.65 | recurrent_cross_signal_cluster |
| 12 | Comp291378 | 10 | 10 | 27 | 11.60 | recurrent_cross_signal_cluster |
| 13 | Comp995183 | 16 | 16 | 28 | 11.55 | recurrent_cross_signal_cluster |
| 14 | Comp805594 | 15 | 15 | 29 | 11.55 | recurrent_cross_signal_cluster |
| 15 | Comp331177 | 5 | 5 | 31 | 11.50 | recurring_candidate_cluster |
| 16 | Comp156925 | 15 | 15 | 34 | 11.45 | recurrent_cross_signal_cluster |
| 17 | Comp623178 | 5 | 5 | 36 | 11.40 | recurring_candidate_cluster |
| 18 | Comp815986 | 5 | 5 | 37 | 11.40 | recurring_candidate_cluster |
| 19 | Comp758969 | 2 | 2 | 38 | 11.40 | distinct_host_window_spike |
| 20 | Comp805669 | 3 | 3 | 39 | 11.40 | recurring_candidate_cluster |

---

## 8. Triage-Tier Distribution

v0.1.2 separates the queue into analyst-facing tiers while preserving the original rows.

| triage_tier | count | share | unique_hosts | score_max |
| --- | --- | --- | --- | --- |
| E_context_queue | 8,957 | 89.57% | 4,478 | 9.00 |
| B_recurrent_high_signal_candidate | 778 | 7.78% | 493 | 12.30 |
| A_distinct_high_signal_candidate | 217 | 2.17% | 208 | 11.90 |
| D_persistent_cluster_member | 46 | 0.46% | 2 | 14.00 |
| C_persistent_cluster_representative | 2 | 0.02% | 2 | 14.00 |

---

## 9. Top-100 Signal Composition

The Top 100 is dominated by cross-signal host/network overlap and privilege/credential/network breadth signals.

| signal | count | share_of_rows |
| --- | --- | --- |
| high_port_diversity | 100 | 100.00% |
| host_network_overlap | 100 | 100.00% |
| special_privileges | 98 | 98.00% |
| high_network_fanout | 95 | 95.00% |
| high_byte_volume | 93 | 93.00% |
| explicit_credentials | 92 | 92.00% |
| smb_heavy | 89 | 89.00% |
| high_process_diversity | 85 | 85.00% |
| high_process_creation | 84 | 84.00% |
| many_users_on_host | 62 | 62.00% |
| many_logon_sources | 50 | 50.00% |
| logon_failure_cluster | 44 | 44.00% |
| several_users_on_host | 37 | 37.00% |
| external_ip_interaction | 28 | 28.00% |
| moderate_process_creation | 15 | 15.00% |

This signal composition indicates coherent structural reconstruction, not random scoring.

---

## 10. Claim Boundary

Correct claim:

```text
SRIA Unified Day-02 v0.1.3a reconstructs host-window episodes from LANL Unified Host and Network telemetry and packages them into ranked, clustered, and diversity-aware analyst review views.
```

Incorrect claim:

```text
SRIA detected attacks on Day 2.
```

Reason:

```text
This Day-02 run has no red-team report or ground-truth attack labels. Therefore, no recall, precision, F1, or confirmed attack classification is reported.
```

---

## 11. Next Validation Steps

1. Run the same v0.1-v0.1.3a pipeline on another Unified Host/Network day, preferably Day 60 or Day 90.
2. Build cross-day cluster recurrence: persistent clusters, disappeared clusters, and newly emergent clusters.
3. Add infrastructure annotation, not suppression, for service-like hosts such as ActiveDirectory, EnterpriseAppServer, scanner-like hosts, and other persistent infrastructure roles.
4. Add delta-based triage: prioritize hosts whose current structural profile deviates from their own cross-day baseline.
5. Compare original ranking, cluster-aware ranking, first-appearance ranking, and round-robin ranking across days.
6. Keep claims no-label unless an independent ground-truth source is introduced.

---

## 12. Current Status

```text
v0.1    Day-02 full reconstruction: complete
v0.1.1  queue diagnostics: complete
v0.1.2  cluster-aware triage: complete
v0.1.3  triage interpretation report: complete
v0.1.3a clean publication-ready report: complete
```

Current best description:

```text
SRIA Unified Day-02 is a no-label host/network reconstruction and analyst-triage packaging run. It demonstrates scale, reconstruction coherence, and presentation-layer burden reduction, but not confirmed detection.
```

