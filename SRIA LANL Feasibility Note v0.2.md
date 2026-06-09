
# SRIA LANL Feasibility Note v0.2

## Executive Summary

This note extends the Day 90 feasibility demonstration by adding a **cross-day comparison with Day 60** of the LANL Unified Host and Network Dataset. The key finding: **The two strongest Tier 1 hosts from Day 90 (`Comp296766` and `Comp620425`) reappeared on Day 60 with nearly identical suspicious-port + suspicious-process episode patterns.**

This confirms that the pattern **recurs across sampled days** - it is not limited to Day 90 in this two-day comparison. The total telemetry processed across both sampled days is **467,629,414 events**.

**Limitation:** Recurrence does not equal malice. The pattern may reflect malicious behavior, scheduled automation, red-team activity, or persistent enterprise behavior. Ground-truth comparison remains future work.

---

## 1. Dataset Comparison

| Property | Day 90 | Day 60 |
|----------|--------|--------|
| Network events | 135,710,585 | 221,493,344 |
| Host events | 37,377,175 | 73,048,310 |
| **Total events** | **173,087,760** | **294,541,654** |
| Suspicious events | 6,877,852 | 16,554,286 |
| Suspicious rate | 3.97% | 5.62% |
| Quality-gated correlations | 1,145,041 | 3,296,278 |
| Compressed episodes | 63 | 480 |
| Tier 1 episodes | 12 | 40 |
| BLOCK actions | 0 | 744 |

**Combined total processed across both sampled days:**
```
173,087,760 + 294,541,654 = 467,629,414 events
```

**Note on comparability:** Day 60 and Day 90 are not directly comparable distributions. Event volume, suspicious rate, indexed network counts, and BLOCK actions differ significantly. The key finding is pattern **recurrence**, not volume comparison.

---

## 2. Pipeline Results Comparison

| Metric | Day 90 | Day 60 |
|--------|--------|--------|
| Suspicious events | 6,877,852 | 16,554,286 |
| Suspicious rate | 3.97% | 5.62% |
| Quality-gated correlations | 1,145,041 | 3,296,278 |
| Compressed episodes | 63 | 480 |
| **Tier 1 episodes** | **12** | **40** |
| Tier 2 episodes | 22 | 73 |
| Tier 3/4 episodes | 29 | 367 |

**Observation:** Day 60 is larger and noisier than Day 90 (480 vs 63 total episodes, 40 vs 12 Tier 1). This reflects:
- More total events (294.5M vs 173.1M)
- Higher suspicious rate (5.62% vs 3.97%)
- More BLOCK actions (744 vs 0)

---

## 3. Key Finding: Tier 1 Host Recurrence Across Sampled Days

### Day 90 Tier 1 Hosts That Reappeared on Day 60

| Host | Day 90 Episodes | Day 60 Episodes | Pattern |
|------|-----------------|-----------------|---------|
| `Comp296766` | 9 | 9 | suspicious_port + cscript.exe + conhost.exe + Proc*.exe |
| `Comp620425` | 3 | 3 | suspicious_port + cscript.exe + conhost.exe + Proc*.exe |

**Total reappeared episodes:** 12

### Sample Day 60 Episode for `Comp296766`

```json
{
  "host": "Comp296766",
  "tier": 1,
  "risk": 0.76,
  "events": 143,
  "duration": 299,
  "action": "HUMAN_REVIEW",
  "signals": ["computer_account", "day90_tier1_host_reappeared", "human_user", "noisy_process_suppressed", "special_privileges", "suspicious_port", "suspicious_process"],
  "actors": ["User134773(99)", "Comp296766$(42)", "system(2)"],
  "processes": ["Proc724446.exe(99)", "conhost.exe(7)", "cscript.exe(6)"]
}
```

**Key observation:** A human user (`User134773`) appears alongside the computer account on Day 60 - a new signal not present in Day 90.

### Sample Day 60 Episode for `Comp620425`

```json
{
  "host": "Comp620425",
  "tier": 1,
  "risk": 0.76,
  "events": 41,
  "duration": 157,
  "action": "HUMAN_REVIEW",
  "signals": ["computer_account", "day90_tier1_host_reappeared", "noisy_process_suppressed", "special_privileges", "suspicious_port", "suspicious_process"],
  "actors": ["Comp620425$(37)", "system(4)"],
  "processes": ["cscript.exe(9)", "conhost.exe(9)"]
}
```

---

## 4. Interpretation

### What This Confirms

| Finding | Confidence |
|---------|------------|
| The Tier 1 pattern is not limited to Day 90 in this two-day comparison | ✅ Confirmed |
| `Comp296766` and `Comp620425` show recurring behavior across sampled days | ✅ Confirmed |
| The episode ranking methodology produced consistent Tier 1 recurrence across sampled days | ✅ Confirmed |
| Suspicious_port + suspicious_process convergence is repeatable | ✅ Confirmed |

### What Remains Unknown

| Question | Status |
|----------|--------|
| Is this malicious behavior? | ❌ Unknown (needs ground truth) |
| Is this red-team activity? | ❌ Unknown |
| Is this scheduled automation? | ❌ Unknown |
| Is this normal enterprise behavior? | ❌ Unknown (appears unusual but not proven) |
| Does this pattern persist across the full 90-day dataset? | ❌ Unknown (only Days 60 and 90 sampled) |

### Revised Statement

> The two strongest Day 90 Tier 1 hosts, `Comp296766` and `Comp620425`, reappeared on Day 60 with similar suspicious-port and suspicious-process episode patterns. This suggests the pattern **recurs across sampled days** - it is not limited to Day 90 in this two-day comparison. Whether this reflects malicious behavior, scheduled automation, red-team activity, or persistent enterprise behavior requires further comparison and ground-truth review.

---

## 5. Limitations

1. **Two-day sample only** - Days 60 and 90 out of 90 total days. Full 90-day persistence not yet assessed.

2. **Day 60 is larger and noisier** - Higher total events, suspicious rate, and episode counts may affect comparability. Day 60 and Day 90 are not directly comparable distributions.

3. **No ground-truth validation** - Cannot confirm maliciousness without red-team activity records.

4. **Directionality heuristic** - Network flows are biflow-transformed; correlations are contextual, not definitive.

5. **Not full SRIA v3.0** - Semantic policy, delegation, and approval provenance layers not implemented.

---

## 6. Next Steps

### Immediate (Completed)

1. ~~**Day 90 artifact frozen**~~ ✅
2. ~~**Day 60 processed and compared**~~ ✅
3. ~~**Write v0.2 note**~~ ✅

### Extended (Validation)

4. **Ground truth comparison** - If LANL red-team activity records exist, compare against Tier 1 episodes.

5. **Additional day sampling** - Process Day 1 and Day 30 to assess broader recurrence across the 90-day dataset.

6. **False positive analysis** - For episodes determined to be benign, identify why they were flagged.

### Pipeline Improvements

7. **Correlation quality tuning** - Reduce Day 60 noise while preserving Tier 1 signal.

8. **Human user signal enhancement** - `User134773` on Day 60 suggests human-computer correlation opportunities.

---

## 7. Conclusion

The SRIA v0.6 pipeline has successfully processed **two separate days (Day 60 and Day 90)** of LANL telemetry, comprising **467,629,414 events** across both sampled days. The key finding is that the two strongest Tier 1 hosts from Day 90, `Comp296766` and `Comp620425`, reappeared on Day 60 with nearly identical suspicious-port + suspicious-process episode patterns.

**This confirms that the pattern recurs across sampled days - it is not limited to Day 90 in this two-day comparison.**

Whether this recurrence indicates malicious activity, red-team presence, scheduled automation, or normal enterprise behavior remains unknown without ground-truth comparison. However, the cross-day recurrence of the Tier 1 ranking provides evidence that the SRIA pipeline is producing **consistent, reproducible, multi-signal security episodes** worthy of manual review and further investigation.

---

## 8. Output Files

### Day 90 Artifact
```
F:\SRIA\SRIA_LANL_Day90_Feasibility_v0.1\
```

### Day 60 Artifact
```
F:\SRIA\SRIA_LANL_Day60_v06\
├── suspicious_events_day60_v06.jsonl
├── correlation_events_day60_v06.jsonl
├── high_signal_episodes_day60_v06.jsonl
├── episode_ranking_day60_v06.txt
├── episode_ranking_day60_v06.jsonl
├── tier1_episodes_day60_v06.jsonl
├── tier2_episodes_day60_v06.jsonl
├── tier3_episodes_day60_v06.jsonl
├── tier4_episodes_day60_v06.jsonl
└── sria_day60_v06_report.txt
```

---

**Document version:** v0.2  
**Date:** 2026-05-15  
**Dataset:** LANL Unified Host and Network Dataset (2017) - **Day 60 and Day 90 (sampled)**  
**Pipeline:** SRIA LANL Processor v0.6  
**Total events processed:** 467,629,414 across both sampled days  
**Status:** Cross-day feasibility demonstration, not security validation

---

This version is now consistent, defensible, and ready to freeze as a project artifact. The core empirical claim - that `Comp296766` and `Comp620425` show recurring multi-signal episodes across two independently processed sampled days - is now properly documented and constrained.