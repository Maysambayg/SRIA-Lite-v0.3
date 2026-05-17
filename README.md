# SRIA Lite v0.6

**Semantic Reconstruction Integrity Architecture — compact defensive decision-governance prototype**

SRIA Lite v0.6 is a runnable Python scaffold that demonstrates the practical decision-governance loop described in the SRIA v3.0 paper.
Status: Alpha research prototype.
SRIA Lite v0.6 is provided for review, experimentation, and noncommercial evaluation. It is not production software and does not reproduce the full SRIA v3.0 benchmark pipeline.
It is **not** the full SRIA v3.0 benchmark pipeline and it is **not** a production security system. It is a defensive research prototype meant to show how SRIA-style components can be represented in code.

## What this prototype demonstrates

SRIA Lite v0.6 includes:

- a semantic integrity spine,
- **provenance-chain validation** (new in v0.6),
- lightweight behavioral memory (enhanced: unknown-actor risk scales with resource criticality),
- graph novelty tracking with **configurable weights** (new in v0.6),
- rolling suspicion memory with decay,
- confidence-gated fusion (now includes provenance risk channel),
- proportional defensive actions with **action-cost scoring** (new in v0.6),
- **explicit priority-ordered governor** with documented precedence (improved in v0.6),
- **CSV/JSON event ingestion** (new in v0.6),
- **configurable scenario files** (new in v0.6),
- **synthetic benchmark runner** with optional frequency-baseline comparison (new in v0.6),
- **CLI interface** (new in v0.6),
- audit logging,
- state persistence,
- JSON and Prometheus-style metrics export,
- **pytest test suite** (new in v0.6).

The action ladder implemented in this prototype includes:

```text
allow          (cost=0.00)
watch          (cost=0.02)
shadow_observe (cost=0.05)
collect_evidence (cost=0.10)
step_up_auth   (cost=0.30)
session_reverify (cost=0.35)
queue_review   (cost=0.45)
human_review   (cost=0.60)
block          (cost=0.85)
privilege_freeze (cost=1.00)
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
sria_lite_v06.py        Core SRIA Lite v0.6 engine
sria_lite_v03.py        Legacy v0.3 engine (preserved for reference)
demo_sria_lite.py       Runnable demonstration script
cli.py                  Command-line interface
scenarios/              Example scenario files
  default.json          Standard demo scenario
  stress_test.json      Multi-event stress-test scenario
tests/
  test_engine.py        Pytest test suite
requirements.txt        Python dependencies
README.md               This file
```

When you run the demo, it creates:

```text
demo_results.json       Per-event decisions and scores
demo_metrics.json       Aggregate metrics
sria_lite_state.json    Saved lightweight engine state
```

## Quick start

Run the demo:

```bash
python demo_sria_lite.py
```

No external Python packages are required for the demo. The prototype uses the Python standard library.

## CLI usage

The CLI provides four commands:

```bash
# Run the built-in demo
python cli.py demo

# Ingest events from a CSV or JSON file
python cli.py ingest events.json
python cli.py ingest events.csv

# Run a scenario file
python cli.py scenario scenarios/default.json

# Run the synthetic benchmark
python cli.py benchmark
python cli.py benchmark --n-normal 500 --n-anomalous 100 --no-baseline
```

All commands accept `--output-dir <path>` to control where output files are written.

## Run tests

Install pytest and run the test suite:

```bash
pip install pytest
pytest tests/ -v
```

The legacy v0.3 built-in smoke tests still work:

```bash
python sria_lite_v03.py
```

## Scenario files

Scenario files are JSON documents that define a policy, optional baseline warmup events, and the events to evaluate:

```json
{
    "policy": { "role_actions": {...}, "role_resources": {...}, ... },
    "config": { ... },
    "baseline_events": [ ... ],
    "events": [ ... ]
}
```

See `scenarios/default.json` and `scenarios/stress_test.json` for examples.

## Event ingestion

Events can be loaded from JSON (list of event objects) or CSV files:

```json
[
    {"actor": "alice", "role": "analyst", "action": "read", "resource": "reports"},
    {"actor": "bob", "role": "engineer", "action": "deploy", "resource": "service_a"}
]
```

CSV files must have a header row with field names matching the Event fields (actor, role, action, resource, resource_criticality, etc.).

## Benchmark

The synthetic benchmark generates labeled normal and anomalous events, evaluates them with SRIA, and computes AUC, TPR, and FPR at configurable thresholds. An optional frequency-based baseline provides a straw-man comparator.

```bash
python cli.py benchmark
```

## What the demo does

The demo warms the engine with a few normal baseline events, then evaluates five events:

1. normal analyst read,
2. unauthorized analyst delete,
3. engineer deploy during freeze,
4. admin grant on a critical identity resource from an unfamiliar device/IP,
5. engineer access from a new device/IP.

For each event, the demo prints:

- selected action and **action cost**,
- semantic risk,
- behavioral risk,
- graph risk,
- **provenance risk**,
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
| **Provenance-Chain Validation** | `provenance_chain_check()` (new in v0.6) |
| Graph Representation / Memory | `GraphMemory` |
| Confidence-Gated Fusion | `confidence_gate()` + `fuse()` |
| Action-Specific Governor | `action_specific_governor()` (priority-ordered in v0.6) |
| **Action-Cost Scoring** | `ACTION_COST` dict + `Decision.action_cost` (new in v0.6) |
| Metrics / Audit | `export_metrics()`, `export_metrics_prometheus()`, audit log |
| Persistence | `save_state()`, `load_state()` |
| **Synthetic Benchmarks** | `run_benchmark()`, `FrequencyBaseline` (new in v0.6) |

## What changed from v0.3 to v0.6

1. **Provenance-chain validation** — validates that events have coherent authority chains; gaps accumulate provenance risk scaled by resource criticality.
2. **Action-cost scoring** — each action in the ladder has a numeric friction cost (0.0–1.0), exposed in every Decision and aggregated in metrics.
3. **Configurable graph weights** — graph-novelty weights (previously hard-coded) are now tunable parameters in `SRIAConfig`.
4. **Explicit priority-ordered governor** — the governor's if/return chain now has documented priority levels (1–12) with clear precedence rules.
5. **Enhanced behavioral companion** — unknown-actor baseline risk now scales with `resource_criticality` instead of being a flat constant.
6. **Five-channel fusion** — fusion now includes a provenance-risk channel (`epsilon_provenance`) alongside semantic, behavioral, graph, and agreement.
7. **CSV/JSON event ingestion** — `load_events_json()`, `load_events_csv()`, and auto-detecting `load_events()`.
8. **Configurable scenario files** — JSON scenario format with policy, config, baseline events, and evaluation events.
9. **Synthetic benchmark runner** — generates labeled normal/anomalous events, computes AUC/TPR/FPR, optional frequency-baseline comparison.
10. **CLI interface** — `cli.py` with `demo`, `ingest`, `scenario`, and `benchmark` commands.
11. **pytest test suite** — structured tests covering engine, fusion, governor, provenance, persistence, ingestion, scenarios, and benchmarks.
12. **`.gitignore`** — ignores `__pycache__/`, generated output files, IDE artifacts.

## Correct interpretation

Use this package as:

> a minimal executable reference scaffold for SRIA-style defensive decision governance.

Do **not** use it as evidence that SRIA v3.0 has been externally validated.

The paper's benchmark results require a separate reproducibility package with synthetic data generation, baselines, AUC/FPR/TPR evaluation, ablation testing, and full scenario scripts.

## Suggested next upgrade

The next useful prototype step is `SRIA Lite v0.7`, adding:

- full provenance-graph traversal (not just gap counting),
- YAML scenario support,
- configurable action-cost overrides,
- ablation testing framework,
- multi-engine comparison dashboard,
- event replay from audit logs.
