---
name: testing-sria-lite
description: End-to-end testing procedure for SRIA Lite engine, CLI, scenarios, benchmark, ingestion, persistence, and metrics. Use when verifying changes to the SRIA Lite engine or CLI.
---

# Testing SRIA Lite

## Prerequisites

- Python 3.10+
- `pip install pytest` (only dependency beyond stdlib)

## Quick Smoke Test

```bash
pytest tests/ -v
python demo_sria_lite.py
```

## Full End-to-End Test Procedure

All testing is shell-based (no GUI/browser needed). No recording required.

### 1. Demo Script

```bash
python demo_sria_lite.py
```

**Verify:**
- Exit code 0
- 5 events evaluated with proportional decisions:
  - Normal read → allow (cost=0.00)
  - Unauthorized delete → human_review or higher (cost >= 0.60)
  - Deploy during freeze → block (cost=0.85)
  - Unknown actor admin grant → queue_review or higher
  - New device → session_reverify (cost=0.35)
- Files created: demo_results.json, demo_metrics.json, sria_lite_state.json

### 2. CLI Commands

Note: `--output-dir` must come **before** the subcommand (argparse parent parser).

```bash
mkdir -p /tmp/sria_test

# Demo
python cli.py --output-dir /tmp/sria_test demo

# Scenarios
python cli.py --output-dir /tmp/sria_test scenario scenarios/default.json
python cli.py --output-dir /tmp/sria_test scenario scenarios/stress_test.json

# Benchmark (with and without baseline)
python cli.py --output-dir /tmp/sria_test benchmark --n-normal 100 --n-anomalous 30 --seed 42
python cli.py --output-dir /tmp/sria_test benchmark --no-baseline --n-normal 50 --n-anomalous 20

# Ingest JSON
echo '[{"actor":"alice","role":"analyst","action":"read","resource":"reports"}]' > /tmp/sria_test/events.json
python cli.py --output-dir /tmp/sria_test ingest /tmp/sria_test/events.json

# Ingest CSV
echo 'actor,role,action,resource\nalice,analyst,read,reports' > /tmp/sria_test/events.csv
python cli.py --output-dir /tmp/sria_test ingest /tmp/sria_test/events.csv

# No command → help + exit code 1
python cli.py
```

### 3. Key Assertions

- **Benchmark AUC**: SRIA AUC should be > 0.5 (typically ~0.96). If significantly lower, the engine's detection capability may have regressed.
- **Governor proportionality**: Decisions should escalate proportionally — allow for benign events, block/freeze for frozen resources, review for unknowns.
- **State persistence**: `sria_lite_state.json` should roundtrip — load it back and verify the engine can still evaluate events.
- **Prometheus metrics**: `export_metrics_prometheus()` outputs lines with `sria_` prefix in standard Prometheus text format.

### 4. Pytest Suite

```bash
pytest tests/ -v
```

Expect 40+ tests covering: utilities, config validation, fusion, governor, provenance, action costs, behavioral companion, persistence, metrics, graph memory, ingestion, scenarios, benchmarks.

## Notes

- The engine uses only the Python standard library (no external deps except pytest for tests)
- Generated output files (demo_results.json, etc.) are in .gitignore — do not commit them
- The v0.3 engine (sria_lite_v03.py) is preserved as a reference; demo_sria_lite.py imports from the latest version
- No CI is currently configured on this repo — tests must be verified locally
