"""
Runnable demo for SRIA Lite v0.3.

This script demonstrates the defensive decision-governance loop:
semantic checks + behavioral memory + graph novelty + confidence-gated fusion
+ proportional action selection.

Run:
    python demo_sria_lite.py

Outputs:
    demo_results.json
    demo_metrics.json
    sria_lite_state.json
"""

from __future__ import annotations

import json
from pathlib import Path

from sria_lite_v03 import (
    Event,
    MissionState,
    PolicyState,
    SRIAConfig,
    SRIALite,
)


OUT_DIR = Path(__file__).resolve().parent


def build_engine() -> SRIALite:
    """Build a small demo policy and warm the engine with normal baseline activity."""
    policy = PolicyState(
        role_actions={
            "analyst": {"read", "export"},
            "engineer": {"read", "deploy"},
            "admin": {"read", "deploy", "delete", "grant_admin"},
            "auditor": {"read", "audit"},
        },
        role_resources={
            "analyst": {"reports", "metrics"},
            "engineer": {"service_a", "service_b"},
            "admin": {"*"},
            "auditor": {"reports", "logs"},
        },
        frozen_resources={"service_b"},
        required_approval_actions={"deploy", "delete", "export", "grant_admin"},
        active_approvals={"APPROVAL-123"},
        active_delegations={"DEL-OK"},
    )

    config = SRIAConfig()
    engine = SRIALite(policy=policy, config=config)

    baseline_events = [
        Event(
            actor="alice",
            role="analyst",
            action="read",
            resource="reports",
            device_id="alice_laptop",
            source_ip="10.0.0.10",
        ),
        Event(
            actor="alice",
            role="analyst",
            action="export",
            resource="reports",
            approval_id="APPROVAL-123",
            device_id="alice_laptop",
            source_ip="10.0.0.10",
        ),
        Event(
            actor="bob",
            role="engineer",
            action="read",
            resource="service_a",
            device_id="bob_laptop",
            source_ip="10.0.0.20",
        ),
        Event(
            actor="bob",
            role="engineer",
            action="read",
            resource="service_a",
            device_id="bob_laptop",
            source_ip="10.0.0.20",
        ),
        Event(
            actor="dina",
            role="auditor",
            action="audit",
            resource="logs",
            device_id="dina_laptop",
            source_ip="10.0.0.30",
        ),
    ]

    for event in baseline_events:
        engine.evaluate(event)

    return engine


def scenario_events() -> list[tuple[str, Event]]:
    """Return labeled demo events."""
    return [
        (
            "normal_analyst_read",
            Event(
                actor="alice",
                role="analyst",
                action="read",
                resource="reports",
                device_id="alice_laptop",
                source_ip="10.0.0.10",
            ),
        ),
        (
            "unauthorized_analyst_delete",
            Event(
                actor="alice",
                role="analyst",
                action="delete",
                resource="reports",
                resource_criticality=0.70,
                device_id="alice_laptop",
                source_ip="10.0.0.10",
            ),
        ),
        (
            "engineer_deploy_during_freeze",
            Event(
                actor="bob",
                role="engineer",
                action="deploy",
                resource="service_b",
                resource_criticality=0.90,
                approval_id="APPROVAL-123",
                mission_state=MissionState.FREEZE,
                device_id="bob_laptop",
                source_ip="10.0.0.20",
            ),
        ),
        (
            "critical_admin_grant_from_unfamiliar_context",
            Event(
                actor="carol",
                role="admin",
                action="grant_admin",
                resource="identity",
                resource_criticality=1.00,
                device_id="unknown_device",
                source_ip="203.0.113.10",
            ),
        ),
        (
            "known_engineer_new_device_same_resource",
            Event(
                actor="bob",
                role="engineer",
                action="read",
                resource="service_a",
                resource_criticality=0.60,
                device_id="new_device",
                source_ip="10.0.0.99",
            ),
        ),
    ]


def main() -> None:
    engine = build_engine()
    results = []

    print("\nSRIA Lite v0.3 demo")
    print("=" * 72)

    for idx, (label, event) in enumerate(scenario_events(), start=1):
        decision = engine.evaluate(event)
        row = {
            "index": idx,
            "label": label,
            "event": event.to_jsonable(),
            "decision": decision.to_jsonable(),
        }
        results.append(row)

        print(f"\n[{idx}] {label}")
        print(f"    actor={event.actor} role={event.role} action={event.action} resource={event.resource}")
        print(f"    action={decision.action.value}")
        print(
            "    scores="
            f"semantic:{decision.semantic_risk:.3f} "
            f"behavioral:{decision.behavioral_risk:.3f} "
            f"graph:{decision.graph_risk:.3f} "
            f"fusion:{decision.fusion_risk:.3f} "
            f"confidence:{decision.confidence:.3f} "
            f"uncertainty:{decision.uncertainty:.3f}"
        )
        print(f"    reason_codes={[code.value for code in decision.reason_codes]}")
        for reason in decision.reasons:
            print(f"      - {reason}")

    metrics = engine.export_metrics()

    (OUT_DIR / "demo_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (OUT_DIR / "demo_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    engine.save_state(OUT_DIR / "sria_lite_state.json")

    print("\nGenerated files:")
    print("  - demo_results.json")
    print("  - demo_metrics.json")
    print("  - sria_lite_state.json")

    print("\nMetrics summary:")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
