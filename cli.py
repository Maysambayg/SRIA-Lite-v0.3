"""
SRIA Lite v0.6 — Command-line interface.

Usage examples:

    python cli.py demo
    python cli.py ingest events.json
    python cli.py ingest events.csv
    python cli.py scenario scenarios/default.json
    python cli.py benchmark
    python cli.py benchmark --no-baseline --n-normal 500 --n-anomalous 100
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sria_lite_v06 import (
    Event,
    MissionState,
    PolicyState,
    SRIAConfig,
    SRIALite,
    build_demo_engine,
    load_events,
    run_benchmark,
    run_scenario,
)


def cmd_demo(args: argparse.Namespace) -> None:
    """Run the built-in demo."""
    engine = build_demo_engine()
    test_events = [
        Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="alice", role="analyst", action="delete", resource="reports", resource_criticality=0.7, device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="bob", role="engineer", action="deploy", resource="service_b", resource_criticality=0.9, approval_id="APPROVAL-123", mission_state=MissionState.FREEZE, device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="carol", role="admin", action="grant_admin", resource="identity", resource_criticality=1.0, device_id="unknown", source_ip="203.0.113.10"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", resource_criticality=0.6, device_id="new_device", source_ip="10.0.0.99"),
    ]

    print("\nSRIA Lite v0.6 demo")
    print("=" * 72)

    results = []
    for idx, event in enumerate(test_events, start=1):
        decision = engine.evaluate(event)
        results.append({"index": idx, "event": event.to_jsonable(), "decision": decision.to_jsonable()})
        print(f"\n[{idx}] actor={event.actor} role={event.role} action={event.action} resource={event.resource}")
        print(f"    action={decision.action.value} (cost={decision.action_cost:.2f})")
        print(
            f"    scores: semantic={decision.semantic_risk:.3f} behavioral={decision.behavioral_risk:.3f} "
            f"graph={decision.graph_risk:.3f} provenance={decision.provenance_risk:.3f} "
            f"fusion={decision.fusion_risk:.3f} confidence={decision.confidence:.3f}"
        )
        print(f"    reason_codes={[c.value for c in decision.reason_codes]}")
        for reason in decision.reasons:
            print(f"      - {reason}")

    out_dir = Path(args.output_dir)
    (out_dir / "demo_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out_dir / "demo_metrics.json").write_text(json.dumps(engine.export_metrics(), indent=2), encoding="utf-8")
    engine.save_state(out_dir / "sria_lite_state.json")
    print(f"\nSaved results to {out_dir}")


def cmd_ingest(args: argparse.Namespace) -> None:
    """Ingest events from a CSV or JSON file and evaluate them."""
    events = load_events(args.file)
    print(f"Loaded {len(events)} event(s) from {args.file}")

    policy = PolicyState(
        role_actions={"analyst": {"read", "export"}, "engineer": {"read", "deploy"}, "admin": {"read", "deploy", "delete", "grant_admin"}, "auditor": {"read", "audit"}},
        role_resources={"analyst": {"reports", "metrics"}, "engineer": {"service_a", "service_b"}, "admin": {"*"}, "auditor": {"reports", "logs"}},
        frozen_resources={"service_b"},
        required_approval_actions={"deploy", "delete", "export", "grant_admin"},
        active_approvals={"APPROVAL-123"},
        active_delegations={"DEL-OK"},
    )
    engine = SRIALite(policy=policy)
    results = []
    for idx, event in enumerate(events, start=1):
        decision = engine.evaluate(event)
        results.append({"index": idx, "event": event.to_jsonable(), "decision": decision.to_jsonable()})
        print(f"[{idx}] actor={event.actor} action={event.action} -> {decision.action.value} (fusion={decision.fusion_risk:.3f})")

    out = Path(args.output_dir) / "ingest_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved {len(results)} result(s) to {out}")


def cmd_scenario(args: argparse.Namespace) -> None:
    """Run a scenario file."""
    engine, decisions = run_scenario(args.file)
    print(f"Scenario {args.file}: {len(decisions)} event(s) evaluated")
    for idx, decision in enumerate(decisions, start=1):
        print(f"  [{idx}] {decision.action.value} (fusion={decision.fusion_risk:.3f}, cost={decision.action_cost:.2f})")

    out = Path(args.output_dir) / "scenario_results.json"
    out.write_text(
        json.dumps([d.to_jsonable() for d in decisions], indent=2),
        encoding="utf-8",
    )
    metrics_out = Path(args.output_dir) / "scenario_metrics.json"
    metrics_out.write_text(json.dumps(engine.export_metrics(), indent=2), encoding="utf-8")
    print(f"Saved results to {out}")


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Run the synthetic benchmark."""
    policy = PolicyState(
        role_actions={"analyst": {"read", "export"}, "engineer": {"read", "deploy"}, "admin": {"read", "deploy", "delete", "grant_admin"}, "auditor": {"read", "audit"}},
        role_resources={"analyst": {"reports", "metrics"}, "engineer": {"service_a", "service_b"}, "admin": {"*"}, "auditor": {"reports", "logs"}},
        frozen_resources={"service_b"},
        required_approval_actions={"deploy", "delete", "export", "grant_admin"},
        active_approvals={"APPROVAL-123"},
        active_delegations={"DEL-OK"},
    )
    result = run_benchmark(
        policy=policy,
        n_normal=args.n_normal,
        n_anomalous=args.n_anomalous,
        seed=args.seed,
        include_baseline=not args.no_baseline,
    )

    print("\nSRIA Lite v0.6 benchmark")
    print("=" * 72)
    print(f"Normal events: {result['n_normal']}")
    print(f"Anomalous events: {result['n_anomalous']}")
    print(f"\nSRIA AUC: {result['sria']['auc']}")
    print(f"SRIA @ threshold 0.25: {json.dumps(result['sria']['metrics_at_0.25'])}")
    print(f"SRIA @ threshold 0.50: {json.dumps(result['sria']['metrics_at_0.50'])}")
    if "frequency_baseline" in result:
        print(f"\nFrequency Baseline AUC: {result['frequency_baseline']['auc']}")
        print(f"Baseline @ threshold 0.25: {json.dumps(result['frequency_baseline']['metrics_at_0.25'])}")
        print(f"Baseline @ threshold 0.50: {json.dumps(result['frequency_baseline']['metrics_at_0.50'])}")

    out = Path(args.output_dir) / "benchmark_results.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nFull results saved to {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sria-lite",
        description="SRIA Lite v0.6 — Semantic Reconstruction Integrity Architecture CLI",
    )
    parser.add_argument("--output-dir", default=".", help="Directory for output files (default: current dir)")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("demo", help="Run the built-in demo")

    p_ingest = sub.add_parser("ingest", help="Ingest events from a CSV or JSON file")
    p_ingest.add_argument("file", help="Path to CSV or JSON event file")

    p_scenario = sub.add_parser("scenario", help="Run a scenario file")
    p_scenario.add_argument("file", help="Path to scenario JSON file")

    p_bench = sub.add_parser("benchmark", help="Run the synthetic benchmark")
    p_bench.add_argument("--n-normal", type=int, default=200, help="Number of normal events (default: 200)")
    p_bench.add_argument("--n-anomalous", type=int, default=50, help="Number of anomalous events (default: 50)")
    p_bench.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    p_bench.add_argument("--no-baseline", action="store_true", help="Skip frequency baseline comparison")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {"demo": cmd_demo, "ingest": cmd_ingest, "scenario": cmd_scenario, "benchmark": cmd_benchmark}[args.command](args)


if __name__ == "__main__":
    main()
