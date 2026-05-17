"""Pytest test suite for SRIA Lite v0.6."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from sria_lite_v06 import (
    Action,
    SRIAConfig,
    SRIALite,
    Event,
    FrequencyBaseline,
    GraphMemory,
    MissionState,
    PolicyState,
    ReasonCode,
    clamp01,
    generate_synthetic_events,
    load_events_csv,
    load_events_json,
    load_scenario,
    run_benchmark,
    run_scenario,
    shannon_entropy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def demo_policy() -> PolicyState:
    return PolicyState(
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


@pytest.fixture
def warmed_engine(demo_policy: PolicyState) -> SRIALite:
    engine = SRIALite(demo_policy)
    baseline = [
        Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="alice", role="analyst", action="export", resource="reports", approval_id="APPROVAL-123", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
    ]
    for event in baseline:
        engine.evaluate(event)
    return engine


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------


class TestUtilities:
    def test_clamp01_lower(self) -> None:
        assert clamp01(-0.5) == 0.0

    def test_clamp01_upper(self) -> None:
        assert clamp01(1.5) == 1.0

    def test_clamp01_pass(self) -> None:
        assert clamp01(0.5) == 0.5

    def test_shannon_entropy_empty(self) -> None:
        assert shannon_entropy([]) == 0.0

    def test_shannon_entropy_uniform(self) -> None:
        assert shannon_entropy(["a", "b"]) == 1.0

    def test_shannon_entropy_single(self) -> None:
        assert shannon_entropy(["a", "a", "a"]) == 0.0


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestConfig:
    def test_default_config_valid(self) -> None:
        cfg = SRIAConfig()
        total = cfg.alpha_semantic + cfg.beta_behavioral + cfg.gamma_agreement + cfg.delta_graph + cfg.epsilon_provenance
        assert math.isclose(total, 1.0, abs_tol=1e-9)

    def test_bad_weights_rejected(self) -> None:
        with pytest.raises(ValueError, match="Fusion weights must sum to 1.0"):
            SRIAConfig(alpha_semantic=0.5, beta_behavioral=0.5, gamma_agreement=0.1, delta_graph=0.1, epsilon_provenance=0.1)

    def test_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError):
            SRIAConfig(suspicion_decay=1.5)

    def test_small_history_window_rejected(self) -> None:
        with pytest.raises(ValueError, match="history_window"):
            SRIAConfig(history_window=2)

    def test_roundtrip_json(self) -> None:
        cfg = SRIAConfig()
        restored = SRIAConfig.from_jsonable(cfg.to_jsonable())
        assert restored.alpha_semantic == cfg.alpha_semantic
        assert restored.epsilon_provenance == cfg.epsilon_provenance


# ---------------------------------------------------------------------------
# Confidence and fusion tests
# ---------------------------------------------------------------------------


class TestFusion:
    def test_low_risk_high_confidence(self, warmed_engine: SRIALite) -> None:
        conf = warmed_engine.confidence_gate(0.0, 0.0, 0.0, 0.0)
        assert conf > 0.9

    def test_high_risk_low_confidence(self, warmed_engine: SRIALite) -> None:
        conf = warmed_engine.confidence_gate(0.9, 0.9, 0.9, 0.9)
        low_risk_conf = warmed_engine.confidence_gate(0.1, 0.1, 0.1, 0.1)
        assert conf < low_risk_conf

    def test_disagreement_lowers_confidence(self, warmed_engine: SRIALite) -> None:
        agree = warmed_engine.confidence_gate(0.5, 0.5, 0.5, 0.5)
        disagree = warmed_engine.confidence_gate(0.9, 0.1, 0.5, 0.3)
        assert agree > disagree

    def test_fuse_all_ones(self, warmed_engine: SRIALite) -> None:
        fused = warmed_engine.fuse(1.0, 1.0, 1.0, 1.0, confidence=1.0)
        assert math.isclose(fused, 1.0, abs_tol=1e-9)

    def test_fuse_all_zeros(self, warmed_engine: SRIALite) -> None:
        fused = warmed_engine.fuse(0.0, 0.0, 0.0, 0.0, confidence=1.0)
        assert math.isclose(fused, 0.0, abs_tol=1e-9)


# ---------------------------------------------------------------------------
# Governor tests (priority-ordered)
# ---------------------------------------------------------------------------


class TestGovernor:
    def test_normal_read_allowed(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
            learn=False,
        )
        assert decision.action == Action.ALLOW
        assert ReasonCode.NO_ISSUE in decision.reason_codes

    def test_unauthorized_delete_escalated(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="delete", resource="reports", resource_criticality=0.7),
            learn=False,
        )
        assert decision.action in {Action.HUMAN_REVIEW, Action.QUEUE_REVIEW}
        assert ReasonCode.ROLE_ACTION_MISMATCH in decision.reason_codes

    def test_frozen_resource_blocked(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(
                actor="bob", role="engineer", action="deploy", resource="service_b",
                resource_criticality=0.9, approval_id="APPROVAL-123",
                mission_state=MissionState.FREEZE,
            ),
            learn=False,
        )
        assert decision.action == Action.BLOCK
        assert ReasonCode.RESOURCE_FROZEN in decision.reason_codes

    def test_new_device_reverify(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="new_device", source_ip="10.0.0.99"),
            learn=False,
        )
        assert decision.action == Action.SESSION_REVERIFY

    def test_unknown_actor_gets_review(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(actor="carol", role="admin", action="grant_admin", resource="identity", resource_criticality=1.0, device_id="unknown", source_ip="203.0.113.10"),
            learn=False,
        )
        assert decision.action in {Action.QUEUE_REVIEW, Action.HUMAN_REVIEW}


# ---------------------------------------------------------------------------
# Provenance chain tests
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_clean_event_no_provenance_risk(self, warmed_engine: SRIALite) -> None:
        risk, reasons = warmed_engine.provenance_chain_check(
            Event(actor="alice", role="analyst", action="read", resource="reports"),
        )
        assert risk == 0.0
        assert len(reasons) == 0

    def test_multiple_gaps_triggers_provenance(self, warmed_engine: SRIALite) -> None:
        risk, reasons = warmed_engine.provenance_chain_check(
            Event(actor="alice", role="analyst", action="delete", resource="service_a"),
        )
        assert risk > 0.0
        assert any(r.code == ReasonCode.PROVENANCE_CHAIN_BROKEN for r in reasons)

    def test_invalid_delegation_adds_risk(self, warmed_engine: SRIALite) -> None:
        risk, reasons = warmed_engine.provenance_chain_check(
            Event(actor="alice", role="analyst", action="export", resource="reports", delegation_id="BAD-DEL"),
        )
        assert risk > 0.0


# ---------------------------------------------------------------------------
# Action cost tests
# ---------------------------------------------------------------------------


class TestActionCost:
    def test_allow_has_zero_cost(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
            learn=False,
        )
        assert decision.action_cost == 0.0

    def test_block_has_high_cost(self, warmed_engine: SRIALite) -> None:
        decision = warmed_engine.evaluate(
            Event(
                actor="bob", role="engineer", action="deploy", resource="service_b",
                resource_criticality=0.9, approval_id="APPROVAL-123",
                mission_state=MissionState.FREEZE,
            ),
            learn=False,
        )
        assert decision.action_cost >= 0.8

    def test_cost_in_metrics(self, warmed_engine: SRIALite) -> None:
        warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="read", resource="reports"),
            learn=False,
        )
        metrics = warmed_engine.export_metrics()
        assert "mean_action_cost" in metrics


# ---------------------------------------------------------------------------
# Behavioral companion tests
# ---------------------------------------------------------------------------


class TestBehavioralCompanion:
    def test_unknown_actor_risk_scales_with_criticality(self, demo_policy: PolicyState) -> None:
        engine = SRIALite(demo_policy)
        low_crit = Event(actor="new_user", role="analyst", action="read", resource="reports", resource_criticality=0.1)
        high_crit = Event(actor="new_user2", role="admin", action="grant_admin", resource="identity", resource_criticality=1.0)
        _, reasons_low, _ = engine.learned_behavioral_companion_lite(low_crit)
        _, reasons_high, _ = engine.learned_behavioral_companion_lite(high_crit)
        assert reasons_high[0].weight > reasons_low[0].weight


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_load_roundtrip(self, warmed_engine: SRIALite, tmp_path: Path) -> None:
        state_file = tmp_path / "state.json"
        warmed_engine.save_state(state_file)
        loaded = SRIALite.load_state(state_file)
        assert set(loaded.profiles.keys()) == set(warmed_engine.profiles.keys())
        assert loaded.graph.actor_action_edges == warmed_engine.graph.actor_action_edges
        assert loaded.config.suspicion_decay == warmed_engine.config.suspicion_decay
        assert loaded.config.epsilon_provenance == warmed_engine.config.epsilon_provenance
        assert loaded.context_profiles.keys() == warmed_engine.context_profiles.keys()

    def test_state_version_string(self, warmed_engine: SRIALite, tmp_path: Path) -> None:
        state_file = tmp_path / "state.json"
        warmed_engine.save_state(state_file)
        data = json.loads(state_file.read_text())
        assert data["version"] == "sria_lite_v0.6"


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_metrics_populated(self, warmed_engine: SRIALite) -> None:
        warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="read", resource="reports"),
            learn=False,
        )
        metrics = warmed_engine.export_metrics()
        assert metrics["total_events"] >= 1

    def test_prometheus_export(self, warmed_engine: SRIALite) -> None:
        warmed_engine.evaluate(
            Event(actor="alice", role="analyst", action="read", resource="reports"),
            learn=False,
        )
        prom = warmed_engine.export_metrics_prometheus()
        assert "sria_events_total" in prom
        assert "sria_mean_fusion_risk" in prom
        assert "sria_mean_action_cost" in prom


# ---------------------------------------------------------------------------
# Graph memory tests
# ---------------------------------------------------------------------------


class TestGraphMemory:
    def test_graph_uses_config_weights(self, demo_policy: PolicyState) -> None:
        cfg = SRIAConfig(graph_actor_resource_novelty=0.50, graph_actor_action_novelty=0.30, graph_role_action_novelty=0.20)
        engine = SRIALite(demo_policy, config=cfg)
        event = Event(actor="new_actor", role="analyst", action="read", resource="reports")
        risk, reasons = engine.graph.graph_risk(event, cfg)
        assert risk == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Event ingestion tests
# ---------------------------------------------------------------------------


class TestIngestion:
    def test_load_json_events(self, tmp_path: Path) -> None:
        events_data = [
            {"actor": "alice", "role": "analyst", "action": "read", "resource": "reports"},
            {"actor": "bob", "role": "engineer", "action": "deploy", "resource": "service_a"},
        ]
        p = tmp_path / "events.json"
        p.write_text(json.dumps(events_data))
        events = load_events_json(p)
        assert len(events) == 2
        assert events[0].actor == "alice"

    def test_load_csv_events(self, tmp_path: Path) -> None:
        csv_content = "actor,role,action,resource,resource_criticality\nalice,analyst,read,reports,0.5\nbob,engineer,deploy,service_a,0.8\n"
        p = tmp_path / "events.csv"
        p.write_text(csv_content)
        events = load_events_csv(p)
        assert len(events) == 2
        assert events[1].resource_criticality == 0.8


# ---------------------------------------------------------------------------
# Scenario tests
# ---------------------------------------------------------------------------


class TestScenario:
    def test_load_default_scenario(self) -> None:
        scenario_path = Path(__file__).resolve().parent.parent / "scenarios" / "default.json"
        if not scenario_path.exists():
            pytest.skip("scenarios/default.json not found")
        policy, config, baseline, events = load_scenario(scenario_path)
        assert len(events) > 0
        assert "analyst" in policy.role_actions

    def test_run_default_scenario(self) -> None:
        scenario_path = Path(__file__).resolve().parent.parent / "scenarios" / "default.json"
        if not scenario_path.exists():
            pytest.skip("scenarios/default.json not found")
        engine, decisions = run_scenario(scenario_path)
        assert len(decisions) == 5


# ---------------------------------------------------------------------------
# Benchmark tests
# ---------------------------------------------------------------------------


class TestBenchmark:
    def test_generate_synthetic_events(self, demo_policy: PolicyState) -> None:
        normal, anomalous = generate_synthetic_events(demo_policy, n_normal=20, n_anomalous=5, seed=42)
        assert len(normal) == 20
        assert len(anomalous) == 5
        assert all(e.label == "normal" for e in normal)
        assert all(e.label == "anomalous" for e in anomalous)

    def test_run_benchmark(self, demo_policy: PolicyState) -> None:
        result = run_benchmark(demo_policy, n_normal=50, n_anomalous=15, seed=42, include_baseline=True)
        assert "sria" in result
        assert "frequency_baseline" in result
        assert 0.0 <= result["sria"]["auc"] <= 1.0

    def test_frequency_baseline(self) -> None:
        baseline = FrequencyBaseline()
        events = [
            Event(actor="alice", role="analyst", action="read", resource="reports"),
            Event(actor="alice", role="analyst", action="read", resource="reports"),
            Event(actor="alice", role="analyst", action="read", resource="reports"),
        ]
        baseline.train(events)
        common_score = baseline.score(Event(actor="alice", role="analyst", action="read", resource="reports"))
        rare_score = baseline.score(Event(actor="bob", role="engineer", action="deploy", resource="service_a"))
        assert rare_score > common_score
