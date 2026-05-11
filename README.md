# SRIA Lite v0.3

**Semantic Reconstruction Integrity Architecture — compact defensive decision-governance prototype**

SRIA Lite v0.3 is a small, runnable Python scaffold that demonstrates the practical decision-governance loop described in the SRIA v3.0 paper.

It is **not** the full SRIA v3.0 benchmark pipeline and it is **not** a production security system. It is a defensive research prototype meant to show how SRIA-style components can be represented in code.

## What this prototype demonstrates

SRIA Lite v0.3 includes:

- a semantic integrity spine,
- lightweight behavioral memory,
- graph novelty tracking,
- rolling suspicion memory with decay,
- confidence-gated fusion,
- proportional defensive actions,
- audit logging,
- state persistence,
- JSON and Prometheus-style metrics export.

The action ladder implemented in this prototype includes:

```text
allow
watch
shadow_observe
collect_evidence
step_up_auth
session_reverify
queue_review
human_review
block
privilege_freeze
```

`rma_containment` is intentionally omitted from this lightweight prototype because SRIA Lite does not interact with adversaries or implement deception/containment environments.

## Safety boundary

This is a defensive proof-of-concept / research scaffold.

It does **not** implement:

- offensive exploitation,
- payloads,
- adversary interaction,
- automated intrusion,
- hack-back,
- live containment infrastructure.

## Files

```text
sria_lite_v03.py        Core SRIA Lite prototype
demo_sria_lite.py       Runnable demonstration script
requirements.txt        Minimal Python dependencies
README.md               This file
```

When you run the demo, it creates:

```text
demo_results.json       Per-event decisions and scores
demo_metrics.json       Aggregate metrics
sria_lite_state.json    Saved lightweight engine state
```

## Quick start

From this directory:

```bash
python demo_sria_lite.py
```

No external Python packages are required for the demo. The prototype uses the Python standard library.

## Run built-in tests

The source file includes built-in smoke tests:

```bash
python sria_lite_v03.py
```

This runs the internal tests and then runs the original demo included in the source file.

## What the demo does

The demo warms the engine with a few normal baseline events, then evaluates five events:

1. normal analyst read,
2. unauthorized analyst delete,
3. engineer deploy during freeze,
4. admin grant on a critical identity resource from an unfamiliar device/IP,
5. engineer access from a new device/IP.

For each event, the demo prints:

- selected action,
- semantic risk,
- behavioral risk,
- graph risk,
- fusion risk,
- confidence,
- uncertainty,
- reason codes,
- human-readable reasons.

## How this maps to SRIA v3.0

| SRIA v3.0 concept | Prototype implementation |
|---|---|
| Semantic Integrity Spine | `semantic_integrity_spine()` |
| Learned Behavioral Companion | `learned_behavioral_companion_lite()` |
| Graph Representation / Memory | `GraphMemory` |
| Confidence-Gated Fusion | `confidence_gate()` + `fuse()` |
| Action-Specific Governor | `action_specific_governor()` |
| Metrics / Audit | `export_metrics()`, `export_metrics_prometheus()`, audit log |
| Persistence | `save_state()`, `load_state()` |

## Correct interpretation

Use this package as:

> a minimal executable reference scaffold for SRIA-style defensive decision governance.

Do **not** use it as evidence that SRIA v3.0 has been externally validated.

The paper’s benchmark results require a separate reproducibility package with synthetic data generation, baselines, AUC/FPR/TPR evaluation, ablation testing, and full scenario scripts.

## Suggested next upgrade

The next useful prototype step is `SRIA Lite v0.4`, adding:

- explicit provenance-chain validation,
- configurable scenario files,
- action-cost scoring,
- synthetic benchmark runner,
- CSV/JSON event ingestion,
- optional baseline model comparison.
