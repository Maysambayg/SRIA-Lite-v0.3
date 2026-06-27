"""
SRIA Lite v0.6
Semantic Reconstruction Integrity Architecture - compact defensive decision-governance prototype.

Upgrades from v0.3:
- Provenance-chain validation with configurable chain rules.
- Action-cost scoring for proportional friction measurement.
- All tuning parameters (including graph weights) surfaced in SRIAConfig.
- Explicit priority-ordered governor with documented precedence.
- Enhanced behavioral companion: unknown-actor risk scales with resource criticality.
- CSV/JSON event ingestion utilities.
- Configurable scenario file support (JSON).
- Synthetic benchmark runner with optional frequency-baseline comparison.
- Prometheus-style and JSON metrics export.
- State persistence and audit logging.

Safety boundary:
This is a defensive proof-of-concept / research scaffold, not a production security system.
It does not implement offensive deception, payloads, exploitation, or adversary interaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import csv
import io
import json
import math
import time


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def shannon_entropy(values: List[str]) -> float:
    """Normalized Shannon entropy for a small categorical sequence."""
    if not values:
        return 0.0
    counts: Dict[str, int] = {}
    for item in values:
        counts[item] = counts.get(item, 0) + 1
    if len(counts) <= 1:
        return 0.0
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return clamp01(entropy / math.log2(len(counts)))


def enum_value(value: Any) -> str:
    return value.value if isinstance(value, Enum) else str(value)


# ---------------------------------------------------------------------------
# Action ladder, states, reason codes
# ---------------------------------------------------------------------------


class Action(str, Enum):
    ALLOW = "allow"
    WATCH = "watch"
    SHADOW_OBSERVE = "shadow_observe"
    COLLECT_EVIDENCE = "collect_evidence"
    STEP_UP_AUTH = "step_up_auth"
    SESSION_REVERIFY = "session_reverify"
    QUEUE_REVIEW = "queue_review"
    HUMAN_REVIEW = "human_review"
    BLOCK = "block"
    PRIVILEGE_FREEZE = "privilege_freeze"


# Friction cost per action (0.0 = no friction, 1.0 = maximum disruption).
ACTION_COST: Dict[Action, float] = {
    Action.ALLOW: 0.00,
    Action.WATCH: 0.02,
    Action.SHADOW_OBSERVE: 0.05,
    Action.COLLECT_EVIDENCE: 0.10,
    Action.STEP_UP_AUTH: 0.30,
    Action.SESSION_REVERIFY: 0.35,
    Action.QUEUE_REVIEW: 0.45,
    Action.HUMAN_REVIEW: 0.60,
    Action.BLOCK: 0.85,
    Action.PRIVILEGE_FREEZE: 1.00,
}


class MissionState(str, Enum):
    NORMAL = "normal"
    HEIGHTENED = "heightened"
    FREEZE = "freeze"
    AUDIT = "audit"
    MAINTENANCE = "maintenance"


class ReasonCode(str, Enum):
    ROLE_UNKNOWN = "role_unknown"
    ROLE_ACTION_MISMATCH = "role_action_mismatch"
    RESOURCE_SCOPE_MISMATCH = "resource_scope_mismatch"
    RESOURCE_FROZEN = "resource_frozen"
    MISSING_OR_INVALID_APPROVAL = "missing_or_invalid_approval"
    INVALID_DELEGATION = "invalid_delegation"
    MISSION_STATE_CONTRADICTION = "mission_state_contradiction"
    PROVENANCE_CHAIN_BROKEN = "provenance_chain_broken"
    LOW_HISTORY_ACTOR = "low_history_actor"
    ACTOR_ROLE_NOVELTY = "actor_role_novelty"
    ACTOR_ACTION_NOVELTY = "actor_action_novelty"
    ACTOR_RESOURCE_NOVELTY = "actor_resource_novelty"
    CONTEXT_ENTROPY_SHIFT = "context_entropy_shift"
    NEW_DEVICE = "new_device"
    NEW_SOURCE_IP = "new_source_ip"
    BEHAVIORAL_ENTROPY_SHIFT = "behavioral_entropy_shift"
    GRAPH_NOVELTY = "graph_novelty"
    GRAPH_SUSPICION_MEMORY = "graph_suspicion_memory"
    NO_ISSUE = "no_issue"


@dataclass(frozen=True)
class Reason:
    code: ReasonCode
    message: str
    weight: float = 0.0

    def to_jsonable(self) -> Dict[str, Any]:
        return {"code": self.code.value, "message": self.message, "weight": self.weight}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class SRIAConfig:
    """All tunable knobs in one place, including graph and provenance weights."""

    # Fusion weights (must sum to 1.0).
    alpha_semantic: float = 0.40
    beta_behavioral: float = 0.25
    gamma_agreement: float = 0.10
    delta_graph: float = 0.15
    epsilon_provenance: float = 0.10

    # Decay parameters.
    suspicion_decay: float = 0.85
    profile_risk_decay: float = 0.90
    baseline_entropy_decay: float = 0.97

    # History / entropy windows.
    history_window: int = 50
    entropy_window: int = 20
    entropy_shift_threshold: float = 0.35
    context_entropy_shift_threshold: float = 0.30

    # Graph risk weights (previously hard-coded).
    graph_actor_resource_novelty: float = 0.35
    graph_actor_action_novelty: float = 0.25
    graph_role_action_novelty: float = 0.20
    graph_suspicion_memory_factor: float = 0.25

    # Governor thresholds.
    graph_novelty_threshold: float = 0.45
    shadow_fusion_min: float = 0.25
    shadow_fusion_max: float = 0.45
    step_up_fusion_threshold: float = 0.30
    queue_review_threshold: float = 0.50
    human_review_threshold: float = 0.70
    high_criticality_threshold: float = 0.80

    # Provenance chain.
    provenance_missing_approval_weight: float = 0.20
    provenance_missing_delegation_weight: float = 0.15
    provenance_role_gap_weight: float = 0.25
    provenance_criticality_scale: float = 0.40

    # Behavioral companion.
    unknown_actor_base_risk: float = 0.10
    unknown_actor_criticality_scale: float = 0.15

    # Audit.
    audit_log_limit: int = 1000

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        total = (
            self.alpha_semantic
            + self.beta_behavioral
            + self.gamma_agreement
            + self.delta_graph
            + self.epsilon_provenance
        )
        if not math.isclose(total, 1.0, abs_tol=1e-9):
            raise ValueError(f"Fusion weights must sum to 1.0, got {total:.6f}")

        bounded_fields = [
            "suspicion_decay",
            "profile_risk_decay",
            "baseline_entropy_decay",
            "entropy_shift_threshold",
            "context_entropy_shift_threshold",
            "graph_actor_resource_novelty",
            "graph_actor_action_novelty",
            "graph_role_action_novelty",
            "graph_suspicion_memory_factor",
            "graph_novelty_threshold",
            "shadow_fusion_min",
            "shadow_fusion_max",
            "step_up_fusion_threshold",
            "queue_review_threshold",
            "human_review_threshold",
            "high_criticality_threshold",
            "provenance_missing_approval_weight",
            "provenance_missing_delegation_weight",
            "provenance_role_gap_weight",
            "provenance_criticality_scale",
            "unknown_actor_base_risk",
            "unknown_actor_criticality_scale",
        ]
        for name in bounded_fields:
            val = self.__dict__[name]
            if not 0.0 <= val <= 1.0:
                raise ValueError(f"{name} must be in [0,1], got {val}")

        if self.history_window < 5:
            raise ValueError("history_window must be >= 5")
        if self.entropy_window < 5:
            raise ValueError("entropy_window must be >= 5")

    def to_jsonable(self) -> Dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "SRIAConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------


@dataclass
class Event:
    actor: str
    role: str
    action: str
    resource: str
    resource_criticality: float = 0.5
    timestamp: float = field(default_factory=time.time)
    approval_id: Optional[str] = None
    delegation_id: Optional[str] = None
    mission_state: MissionState | str = MissionState.NORMAL
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    source_ip: Optional[str] = None
    label: Optional[str] = None

    def normalized_mission_state(self) -> MissionState:
        if isinstance(self.mission_state, MissionState):
            return self.mission_state
        try:
            return MissionState(str(self.mission_state))
        except ValueError:
            return MissionState.NORMAL

    def context_key(self) -> str:
        return f"{self.actor}|{self.role}|{self.resource}"

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "actor": self.actor,
            "role": self.role,
            "action": self.action,
            "resource": self.resource,
            "resource_criticality": self.resource_criticality,
            "timestamp": self.timestamp,
            "approval_id": self.approval_id,
            "delegation_id": self.delegation_id,
            "mission_state": enum_value(self.mission_state),
            "session_id": self.session_id,
            "device_id": self.device_id,
            "source_ip": self.source_ip,
            "label": self.label,
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "Event":
        ms = data.get("mission_state", "normal")
        try:
            ms = MissionState(ms)
        except ValueError:
            pass
        return cls(
            actor=str(data["actor"]),
            role=str(data["role"]),
            action=str(data["action"]),
            resource=str(data["resource"]),
            resource_criticality=float(data.get("resource_criticality", 0.5)),
            timestamp=float(data.get("timestamp", time.time())),
            approval_id=data.get("approval_id"),
            delegation_id=data.get("delegation_id"),
            mission_state=ms,
            session_id=data.get("session_id"),
            device_id=data.get("device_id"),
            source_ip=data.get("source_ip"),
            label=data.get("label"),
        )

    @classmethod
    def from_csv_row(cls, row: Dict[str, str]) -> "Event":
        ms = row.get("mission_state", "normal")
        try:
            ms = MissionState(ms)
        except ValueError:
            pass
        return cls(
            actor=row["actor"],
            role=row["role"],
            action=row["action"],
            resource=row["resource"],
            resource_criticality=float(row.get("resource_criticality", "0.5")),
            timestamp=float(row.get("timestamp", str(time.time()))),
            approval_id=row.get("approval_id") or None,
            delegation_id=row.get("delegation_id") or None,
            mission_state=ms,
            session_id=row.get("session_id") or None,
            device_id=row.get("device_id") or None,
            source_ip=row.get("source_ip") or None,
            label=row.get("label") or None,
        )


@dataclass
class PolicyState:
    role_actions: Dict[str, Set[str]]
    role_resources: Dict[str, Set[str]]
    frozen_resources: Set[str] = field(default_factory=set)
    required_approval_actions: Set[str] = field(
        default_factory=lambda: {"deploy", "delete", "export", "grant_admin"}
    )
    active_approvals: Set[str] = field(default_factory=set)
    active_delegations: Set[str] = field(default_factory=set)

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "role_actions": {k: sorted(v) for k, v in self.role_actions.items()},
            "role_resources": {k: sorted(v) for k, v in self.role_resources.items()},
            "frozen_resources": sorted(self.frozen_resources),
            "required_approval_actions": sorted(self.required_approval_actions),
            "active_approvals": sorted(self.active_approvals),
            "active_delegations": sorted(self.active_delegations),
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "PolicyState":
        return cls(
            role_actions={k: set(v) for k, v in data.get("role_actions", {}).items()},
            role_resources={k: set(v) for k, v in data.get("role_resources", {}).items()},
            frozen_resources=set(data.get("frozen_resources", [])),
            required_approval_actions=set(data.get("required_approval_actions", [])),
            active_approvals=set(data.get("active_approvals", [])),
            active_delegations=set(data.get("active_delegations", [])),
        )


@dataclass
class ContextProfile:
    recent_actions: List[str] = field(default_factory=list)
    recent_resources: List[str] = field(default_factory=list)
    baseline_entropy: float = 0.0
    event_count: int = 0

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "recent_actions": self.recent_actions[-50:],
            "recent_resources": self.recent_resources[-50:],
            "baseline_entropy": self.baseline_entropy,
            "event_count": self.event_count,
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "ContextProfile":
        return cls(
            recent_actions=list(data.get("recent_actions", [])),
            recent_resources=list(data.get("recent_resources", [])),
            baseline_entropy=float(data.get("baseline_entropy", 0.0)),
            event_count=int(data.get("event_count", 0)),
        )


@dataclass
class ActorProfile:
    known_roles: Set[str] = field(default_factory=set)
    known_actions: Set[str] = field(default_factory=set)
    known_resources: Set[str] = field(default_factory=set)
    known_devices: Set[str] = field(default_factory=set)
    known_ips: Set[str] = field(default_factory=set)
    recent_actions: List[str] = field(default_factory=list)
    recent_resources: List[str] = field(default_factory=list)
    event_count: int = 0
    recent_risk: float = 0.0
    baseline_entropy: float = 0.0

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "known_roles": sorted(self.known_roles),
            "known_actions": sorted(self.known_actions),
            "known_resources": sorted(self.known_resources),
            "known_devices": sorted(self.known_devices),
            "known_ips": sorted(self.known_ips),
            "recent_actions": self.recent_actions[-50:],
            "recent_resources": self.recent_resources[-50:],
            "event_count": self.event_count,
            "recent_risk": self.recent_risk,
            "baseline_entropy": self.baseline_entropy,
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "ActorProfile":
        return cls(
            known_roles=set(data.get("known_roles", [])),
            known_actions=set(data.get("known_actions", [])),
            known_resources=set(data.get("known_resources", [])),
            known_devices=set(data.get("known_devices", [])),
            known_ips=set(data.get("known_ips", [])),
            recent_actions=list(data.get("recent_actions", [])),
            recent_resources=list(data.get("recent_resources", [])),
            event_count=int(data.get("event_count", 0)),
            recent_risk=float(data.get("recent_risk", 0.0)),
            baseline_entropy=float(data.get("baseline_entropy", 0.0)),
        )


@dataclass
class GraphMemory:
    actor_resource_edges: Dict[Tuple[str, str], int] = field(default_factory=dict)
    actor_action_edges: Dict[Tuple[str, str], int] = field(default_factory=dict)
    role_action_edges: Dict[Tuple[str, str], int] = field(default_factory=dict)
    suspicion_by_actor: Dict[str, float] = field(default_factory=dict)

    def graph_risk(self, event: Event, cfg: SRIAConfig) -> Tuple[float, List[Reason]]:
        novelty = 0.0
        reasons: List[Reason] = []
        if (event.actor, event.resource) not in self.actor_resource_edges:
            w = cfg.graph_actor_resource_novelty
            novelty += w
            reasons.append(Reason(
                ReasonCode.GRAPH_NOVELTY,
                f"new actor-resource edge: '{event.actor}' -> '{event.resource}'",
                w,
            ))
        if (event.actor, event.action) not in self.actor_action_edges:
            w = cfg.graph_actor_action_novelty
            novelty += w
            reasons.append(Reason(
                ReasonCode.GRAPH_NOVELTY,
                f"new actor-action edge: '{event.actor}' -> '{event.action}'",
                w,
            ))
        if (event.role, event.action) not in self.role_action_edges:
            w = cfg.graph_role_action_novelty
            novelty += w
            reasons.append(Reason(
                ReasonCode.GRAPH_NOVELTY,
                f"new role-action edge: '{event.role}' -> '{event.action}'",
                w,
            ))
        memory = self.suspicion_by_actor.get(event.actor, 0.0) * cfg.graph_suspicion_memory_factor
        if memory > 0.10:
            reasons.append(Reason(
                ReasonCode.GRAPH_SUSPICION_MEMORY,
                f"rolling actor suspicion memory: {memory:.3f}",
                memory,
            ))
        return clamp01(novelty + memory), reasons

    def update(self, event: Event, risk: float, suspicion_decay: float) -> None:
        key_ar = (event.actor, event.resource)
        self.actor_resource_edges[key_ar] = self.actor_resource_edges.get(key_ar, 0) + 1
        key_aa = (event.actor, event.action)
        self.actor_action_edges[key_aa] = self.actor_action_edges.get(key_aa, 0) + 1
        key_ra = (event.role, event.action)
        self.role_action_edges[key_ra] = self.role_action_edges.get(key_ra, 0) + 1
        old = self.suspicion_by_actor.get(event.actor, 0.0)
        self.suspicion_by_actor[event.actor] = clamp01(
            suspicion_decay * old + (1.0 - suspicion_decay) * risk
        )

    def to_jsonable(self) -> Dict[str, Any]:
        def encode_edges(edges: Dict[Tuple[str, str], int]) -> List[Dict[str, Any]]:
            return [{"left": k[0], "right": k[1], "count": v} for k, v in edges.items()]
        return {
            "actor_resource_edges": encode_edges(self.actor_resource_edges),
            "actor_action_edges": encode_edges(self.actor_action_edges),
            "role_action_edges": encode_edges(self.role_action_edges),
            "suspicion_by_actor": self.suspicion_by_actor,
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "GraphMemory":
        def decode_edges(items: List[Dict[str, Any]]) -> Dict[Tuple[str, str], int]:
            return {(item["left"], item["right"]): int(item["count"]) for item in items}
        return cls(
            actor_resource_edges=decode_edges(data.get("actor_resource_edges", [])),
            actor_action_edges=decode_edges(data.get("actor_action_edges", [])),
            role_action_edges=decode_edges(data.get("role_action_edges", [])),
            suspicion_by_actor={k: float(v) for k, v in data.get("suspicion_by_actor", {}).items()},
        )


@dataclass
class Decision:
    action: Action
    action_cost: float
    semantic_risk: float
    behavioral_risk: float
    graph_risk: float
    provenance_risk: float
    fusion_risk: float
    confidence: float
    uncertainty: float
    entropy: float
    latency_ms: float
    reasons: List[str]
    reason_codes: List[ReasonCode]

    def to_jsonable(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "action_cost": self.action_cost,
            "semantic_risk": self.semantic_risk,
            "behavioral_risk": self.behavioral_risk,
            "graph_risk": self.graph_risk,
            "provenance_risk": self.provenance_risk,
            "fusion_risk": self.fusion_risk,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "entropy": self.entropy,
            "latency_ms": self.latency_ms,
            "reason_codes": [c.value for c in self.reason_codes],
            "reasons": self.reasons,
        }


@dataclass
class Metrics:
    total_events: int = 0
    action_counts: Dict[str, int] = field(default_factory=dict)
    reason_counts: Dict[str, int] = field(default_factory=dict)
    risk_sum: float = 0.0
    confidence_sum: float = 0.0
    latency_ms_sum: float = 0.0
    cost_sum: float = 0.0
    max_fusion_risk: float = 0.0

    def record(self, decision: Decision) -> None:
        self.total_events += 1
        self.action_counts[decision.action.value] = (
            self.action_counts.get(decision.action.value, 0) + 1
        )
        for code in decision.reason_codes:
            self.reason_counts[code.value] = self.reason_counts.get(code.value, 0) + 1
        self.risk_sum += decision.fusion_risk
        self.confidence_sum += decision.confidence
        self.latency_ms_sum += decision.latency_ms
        self.cost_sum += decision.action_cost
        self.max_fusion_risk = max(self.max_fusion_risk, decision.fusion_risk)

    def to_jsonable(self) -> Dict[str, Any]:
        n = max(1, self.total_events)
        return {
            "total_events": self.total_events,
            "action_counts": dict(sorted(self.action_counts.items())),
            "reason_counts": dict(sorted(self.reason_counts.items())),
            "mean_fusion_risk": round(self.risk_sum / n, 6),
            "mean_confidence": round(self.confidence_sum / n, 6),
            "mean_latency_ms": round(self.latency_ms_sum / n, 6),
            "mean_action_cost": round(self.cost_sum / n, 6),
            "max_fusion_risk": round(self.max_fusion_risk, 6),
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "Metrics":
        m = cls()
        m.total_events = int(data.get("total_events", 0))
        m.action_counts = {k: int(v) for k, v in data.get("action_counts", {}).items()}
        m.reason_counts = {k: int(v) for k, v in data.get("reason_counts", {}).items()}
        return m


# ---------------------------------------------------------------------------
# SRIA Lite Engine
# ---------------------------------------------------------------------------


# Governor priority documentation:
#
# The action_specific_governor evaluates reason codes and risk scores in the
# following explicit priority order.  Higher-priority rules take precedence;
# the first matching rule returns the action.
#
#   Priority 1 — Mission/freeze violations (RESOURCE_FROZEN, MISSION_STATE_CONTRADICTION)
#                → BLOCK (high criticality/semantic) or HUMAN_REVIEW
#   Priority 2 — Role/action mismatch with high semantic risk
#                → HUMAN_REVIEW
#   Priority 3 — Resource scope mismatch on critical resources
#                → HUMAN_REVIEW or QUEUE_REVIEW
#   Priority 4 — Provenance chain broken on critical resources
#                → HUMAN_REVIEW or QUEUE_REVIEW
#   Priority 5 — Invalid delegation / missing approval
#                → HUMAN_REVIEW (critical) or QUEUE_REVIEW
#   Priority 6 — Identity-continuity concerns (new device / new IP)
#                → SESSION_REVERIFY
#   Priority 7 — Actor-role or actor-action novelty
#                → STEP_UP_AUTH (high fusion) or WATCH
#   Priority 8 — High graph novelty or moderate fusion in shadow range
#                → SHADOW_OBSERVE
#   Priority 9 — Behavioral-only risk without semantic signal
#                → COLLECT_EVIDENCE
#   Priority 10 — High fusion with low confidence
#                → HUMAN_REVIEW
#   Priority 11 — Moderate fusion risk
#                → QUEUE_REVIEW
#   Priority 12 — Low fusion risk above minimum
#                → WATCH
#   Default    — ALLOW


class SRIALite:
    def __init__(self, policy: PolicyState, config: Optional[SRIAConfig] = None):
        self.policy = policy
        self.config = config or SRIAConfig()
        self.config.validate()
        self.profiles: Dict[str, ActorProfile] = {}
        self.context_profiles: Dict[str, ContextProfile] = {}
        self.graph = GraphMemory()
        self.metrics = Metrics()
        self.audit_log: List[Dict[str, Any]] = []
        self._lock = RLock()

    # ----- public API -----

    def evaluate(self, event: Event, learn: bool = True) -> Decision:
        start = time.perf_counter()
        with self._lock:
            semantic_risk, semantic_reasons = self.semantic_integrity_spine(event)
            behavioral_risk, behavioral_reasons, entropy = self.learned_behavioral_companion_lite(event)
            graph_risk, graph_reasons = self.graph.graph_risk(event, self.config)
            provenance_risk, provenance_reasons = self.provenance_chain_check(event)
            confidence = self.confidence_gate(semantic_risk, behavioral_risk, graph_risk, provenance_risk)
            fusion_risk = self.fuse(semantic_risk, behavioral_risk, graph_risk, provenance_risk, confidence)
            all_reasons = semantic_reasons + behavioral_reasons + graph_reasons + provenance_reasons
            action = self.action_specific_governor(
                event, semantic_risk, behavioral_risk, graph_risk,
                provenance_risk, fusion_risk, confidence, all_reasons,
            )

            if learn:
                self.update_memory(event, fusion_risk)

            if not all_reasons:
                all_reasons = [Reason(ReasonCode.NO_ISSUE, "no material reconstruction-integrity issue detected")]

            latency_ms = (time.perf_counter() - start) * 1000.0
            decision = Decision(
                action=action,
                action_cost=ACTION_COST[action],
                semantic_risk=round(semantic_risk, 3),
                behavioral_risk=round(behavioral_risk, 3),
                graph_risk=round(graph_risk, 3),
                provenance_risk=round(provenance_risk, 3),
                fusion_risk=round(fusion_risk, 3),
                confidence=round(confidence, 3),
                uncertainty=round(1.0 - confidence, 3),
                entropy=round(entropy, 3),
                latency_ms=round(latency_ms, 3),
                reasons=[r.message for r in all_reasons],
                reason_codes=[r.code for r in all_reasons],
            )
            self.metrics.record(decision)
            if learn:
                self._append_audit(event, decision)
            return decision

    def evaluate_batch(self, events: Iterable[Event], learn: bool = True) -> List[Decision]:
        return [self.evaluate(event, learn=learn) for event in events]

    # ----- spine -----

    def semantic_integrity_spine(self, event: Event) -> Tuple[float, List[Reason]]:
        risk = 0.0
        reasons: List[Reason] = []

        if event.role not in self.policy.role_actions:
            risk += 0.25
            reasons.append(Reason(ReasonCode.ROLE_UNKNOWN, f"unknown role: '{event.role}'", 0.25))

        allowed_actions = self.policy.role_actions.get(event.role, set())
        if event.action not in allowed_actions:
            risk += 0.35
            reasons.append(Reason(
                ReasonCode.ROLE_ACTION_MISMATCH,
                f"role/action mismatch: role '{event.role}' is not allowed to perform '{event.action}'",
                0.35,
            ))

        allowed_resources = self.policy.role_resources.get(event.role, set())
        if "*" not in allowed_resources and event.resource not in allowed_resources:
            risk += 0.30
            reasons.append(Reason(
                ReasonCode.RESOURCE_SCOPE_MISMATCH,
                f"resource-scope mismatch: role '{event.role}' is not scoped to '{event.resource}'",
                0.30,
            ))

        if event.resource in self.policy.frozen_resources:
            risk += 0.55
            reasons.append(Reason(
                ReasonCode.RESOURCE_FROZEN,
                f"mission/freeze violation: resource '{event.resource}' is frozen",
                0.55,
            ))

        if event.action in self.policy.required_approval_actions:
            if not event.approval_id or event.approval_id not in self.policy.active_approvals:
                risk += 0.30
                reasons.append(Reason(
                    ReasonCode.MISSING_OR_INVALID_APPROVAL,
                    f"missing or invalid approval for sensitive action '{event.action}'",
                    0.30,
                ))

        if event.delegation_id and event.delegation_id not in self.policy.active_delegations:
            risk += 0.25
            reasons.append(Reason(
                ReasonCode.INVALID_DELEGATION,
                f"invalid delegation lifecycle: delegation '{event.delegation_id}' is not active",
                0.25,
            ))

        mission_state = event.normalized_mission_state()
        if mission_state == MissionState.FREEZE and event.action not in {"read", "audit", "reverify"}:
            risk += 0.45
            reasons.append(Reason(
                ReasonCode.MISSION_STATE_CONTRADICTION,
                "mission-state contradiction: non-read action during freeze state",
                0.45,
            ))

        return clamp01(risk), reasons

    # ----- provenance -----

    def provenance_chain_check(self, event: Event) -> Tuple[float, List[Reason]]:
        """Validate the authority chain supporting this event.

        A well-formed chain looks like:
            actor → role (known) → delegation (if present, active) → approval (if needed, valid) → resource (in scope)

        Gaps in the chain accumulate provenance risk, scaled by resource criticality.
        """
        cfg = self.config
        risk = 0.0
        reasons: List[Reason] = []
        gaps = 0

        role_known = event.role in self.policy.role_actions
        if not role_known:
            gaps += 1

        allowed_resources = self.policy.role_resources.get(event.role, set())
        resource_in_scope = "*" in allowed_resources or event.resource in allowed_resources
        if not resource_in_scope:
            gaps += 1

        needs_approval = event.action in self.policy.required_approval_actions
        has_valid_approval = bool(event.approval_id and event.approval_id in self.policy.active_approvals)
        if needs_approval and not has_valid_approval:
            risk += cfg.provenance_missing_approval_weight
            gaps += 1

        has_delegation = bool(event.delegation_id)
        delegation_valid = has_delegation and event.delegation_id in self.policy.active_delegations
        if has_delegation and not delegation_valid:
            risk += cfg.provenance_missing_delegation_weight
            gaps += 1

        if gaps >= 2:
            chain_risk = cfg.provenance_role_gap_weight * (1.0 + cfg.provenance_criticality_scale * event.resource_criticality)
            risk += chain_risk
            reasons.append(Reason(
                ReasonCode.PROVENANCE_CHAIN_BROKEN,
                f"provenance chain has {gaps} gap(s): authority path is incomplete",
                chain_risk,
            ))

        return clamp01(risk), reasons

    # ----- behavioral companion -----

    def learned_behavioral_companion_lite(self, event: Event) -> Tuple[float, List[Reason], float]:
        profile = self.profiles.get(event.actor)
        cfg = self.config
        if profile is None or profile.event_count == 0:
            base = cfg.unknown_actor_base_risk + cfg.unknown_actor_criticality_scale * event.resource_criticality
            return clamp01(base), [Reason(
                ReasonCode.LOW_HISTORY_ACTOR,
                "new or low-history actor: limited behavioral baseline",
                base,
            )], 0.0

        risk = 0.0
        reasons: List[Reason] = []

        if event.role not in profile.known_roles:
            risk += 0.20
            reasons.append(Reason(
                ReasonCode.ACTOR_ROLE_NOVELTY,
                f"actor-role novelty: '{event.actor}' rarely/never used role '{event.role}'",
                0.20,
            ))
        if event.action not in profile.known_actions:
            risk += 0.20
            reasons.append(Reason(
                ReasonCode.ACTOR_ACTION_NOVELTY,
                f"actor-action novelty: '{event.actor}' rarely/never performed '{event.action}'",
                0.20,
            ))
        if event.resource not in profile.known_resources:
            r = 0.20 * (0.5 + clamp01(event.resource_criticality))
            risk += r
            reasons.append(Reason(
                ReasonCode.ACTOR_RESOURCE_NOVELTY,
                f"actor-resource novelty: '{event.actor}' rarely/never accessed '{event.resource}'",
                r,
            ))
        if event.device_id and profile.known_devices and event.device_id not in profile.known_devices:
            risk += 0.20
            reasons.append(Reason(ReasonCode.NEW_DEVICE, f"identity-continuity concern: new device '{event.device_id}'", 0.20))
        if event.source_ip and profile.known_ips and event.source_ip not in profile.known_ips:
            risk += 0.15
            reasons.append(Reason(ReasonCode.NEW_SOURCE_IP, f"identity-continuity concern: new source IP '{event.source_ip}'", 0.15))

        candidate_actions = (profile.recent_actions + [event.action])[-cfg.entropy_window:]
        candidate_resources = (profile.recent_resources + [event.resource])[-cfg.entropy_window:]
        entropy = (shannon_entropy(candidate_actions) + shannon_entropy(candidate_resources)) / 2.0

        if profile.event_count >= 5:
            shift = max(0.0, entropy - profile.baseline_entropy)
            if shift > cfg.entropy_shift_threshold:
                add = min(0.15, 0.30 * shift)
                risk += add
                reasons.append(Reason(
                    ReasonCode.BEHAVIORAL_ENTROPY_SHIFT,
                    f"actor entropy shift: current={entropy:.3f}, baseline={profile.baseline_entropy:.3f}",
                    add,
                ))

        ctx = self.context_profiles.get(event.context_key())
        if ctx and ctx.event_count >= 5:
            ctx_actions = (ctx.recent_actions + [event.action])[-cfg.entropy_window:]
            ctx_resources = (ctx.recent_resources + [event.resource])[-cfg.entropy_window:]
            ctx_entropy = (shannon_entropy(ctx_actions) + shannon_entropy(ctx_resources)) / 2.0
            ctx_shift = max(0.0, ctx_entropy - ctx.baseline_entropy)
            if ctx_shift > cfg.context_entropy_shift_threshold:
                add = min(0.12, 0.25 * ctx_shift)
                risk += add
                reasons.append(Reason(
                    ReasonCode.CONTEXT_ENTROPY_SHIFT,
                    f"actor-context entropy shift: current={ctx_entropy:.3f}, baseline={ctx.baseline_entropy:.3f}",
                    add,
                ))

        risk += 0.25 * profile.recent_risk
        return clamp01(risk), reasons, entropy

    # ----- fusion -----

    def confidence_gate(
        self,
        semantic_risk: float,
        behavioral_risk: float,
        graph_risk: float,
        provenance_risk: float,
    ) -> float:
        risks = [semantic_risk, behavioral_risk, graph_risk, provenance_risk]
        agreement = 1.0 - (max(risks) - min(risks))
        low_risk_strength = 1.0 - max(risks)
        support = 1.0 - abs(semantic_risk - behavioral_risk)
        return clamp01(0.40 * agreement + 0.40 * low_risk_strength + 0.20 * support)

    def fuse(
        self,
        semantic_risk: float,
        behavioral_risk: float,
        graph_risk: float,
        provenance_risk: float,
        confidence: float,
    ) -> float:
        cfg = self.config
        interaction = min(semantic_risk, behavioral_risk) * confidence
        gated_graph = graph_risk * confidence
        raw = (
            cfg.alpha_semantic * semantic_risk
            + cfg.beta_behavioral * behavioral_risk
            + cfg.gamma_agreement * interaction
            + cfg.delta_graph * gated_graph
            + cfg.epsilon_provenance * provenance_risk
        )
        return clamp01(raw)

    # ----- governor (priority-ordered) -----

    def action_specific_governor(
        self,
        event: Event,
        semantic_risk: float,
        behavioral_risk: float,
        graph_risk: float,
        provenance_risk: float,
        fusion_risk: float,
        confidence: float,
        reasons: List[Reason],
    ) -> Action:
        cfg = self.config
        codes = {reason.code for reason in reasons}

        # Priority 1: mission/freeze violations.
        if ReasonCode.RESOURCE_FROZEN in codes or ReasonCode.MISSION_STATE_CONTRADICTION in codes:
            if semantic_risk >= 0.85 or event.resource_criticality >= cfg.high_criticality_threshold:
                return Action.BLOCK
            return Action.HUMAN_REVIEW

        # Priority 2: role/action mismatch with strong semantic signal.
        if ReasonCode.ROLE_ACTION_MISMATCH in codes and semantic_risk >= 0.65:
            return Action.HUMAN_REVIEW

        # Priority 3: resource scope mismatch on critical resources.
        if ReasonCode.RESOURCE_SCOPE_MISMATCH in codes and event.resource_criticality >= cfg.high_criticality_threshold:
            return Action.HUMAN_REVIEW if semantic_risk >= 0.45 else Action.QUEUE_REVIEW

        # Priority 4: broken provenance chain on critical resources.
        if ReasonCode.PROVENANCE_CHAIN_BROKEN in codes and event.resource_criticality >= 0.70:
            return Action.HUMAN_REVIEW if provenance_risk >= 0.40 else Action.QUEUE_REVIEW

        # Priority 5: invalid delegation or missing approval.
        if ReasonCode.INVALID_DELEGATION in codes or ReasonCode.MISSING_OR_INVALID_APPROVAL in codes:
            if semantic_risk >= 0.60 and event.resource_criticality >= 0.70:
                return Action.HUMAN_REVIEW
            return Action.QUEUE_REVIEW

        # Priority 6: identity-continuity concerns.
        if ReasonCode.NEW_DEVICE in codes or ReasonCode.NEW_SOURCE_IP in codes:
            return Action.SESSION_REVERIFY

        # Priority 7: actor-role or actor-action novelty.
        if ReasonCode.ACTOR_ROLE_NOVELTY in codes or ReasonCode.ACTOR_ACTION_NOVELTY in codes:
            return Action.STEP_UP_AUTH if fusion_risk >= cfg.step_up_fusion_threshold else Action.WATCH

        # Priority 8: graph novelty or moderate fusion in shadow range.
        if graph_risk >= cfg.graph_novelty_threshold or (cfg.shadow_fusion_min <= fusion_risk < cfg.shadow_fusion_max):
            return Action.SHADOW_OBSERVE

        # Priority 9: behavioral-only risk without semantic signal.
        if behavioral_risk >= 0.45 and semantic_risk < 0.30:
            return Action.COLLECT_EVIDENCE

        # Priority 10: high fusion with low confidence.
        if fusion_risk >= cfg.human_review_threshold and confidence <= 0.60:
            return Action.HUMAN_REVIEW

        # Priority 11: moderate fusion risk.
        if fusion_risk >= cfg.queue_review_threshold:
            return Action.QUEUE_REVIEW

        # Priority 12: low fusion risk above minimum.
        if fusion_risk >= cfg.shadow_fusion_min:
            return Action.WATCH

        # Default.
        return Action.ALLOW

    # ----- memory -----

    def update_memory(self, event: Event, risk: float) -> None:
        cfg = self.config
        profile = self.profiles.setdefault(event.actor, ActorProfile())
        profile.known_roles.add(event.role)
        profile.known_actions.add(event.action)
        profile.known_resources.add(event.resource)
        if event.device_id:
            profile.known_devices.add(event.device_id)
        if event.source_ip:
            profile.known_ips.add(event.source_ip)
        profile.recent_actions.append(event.action)
        profile.recent_resources.append(event.resource)
        profile.recent_actions = profile.recent_actions[-cfg.history_window:]
        profile.recent_resources = profile.recent_resources[-cfg.history_window:]
        profile.event_count += 1

        self._update_entropy_baseline(profile, cfg)
        profile.recent_risk = clamp01(
            cfg.profile_risk_decay * profile.recent_risk + (1.0 - cfg.profile_risk_decay) * risk
        )

        ctx = self.context_profiles.setdefault(event.context_key(), ContextProfile())
        ctx.recent_actions.append(event.action)
        ctx.recent_resources.append(event.resource)
        ctx.recent_actions = ctx.recent_actions[-cfg.history_window:]
        ctx.recent_resources = ctx.recent_resources[-cfg.history_window:]
        ctx.event_count += 1
        self._update_context_entropy_baseline(ctx, cfg)

        self.graph.update(event, risk, cfg.suspicion_decay)

    @staticmethod
    def _update_entropy_baseline(profile: ActorProfile, cfg: SRIAConfig) -> None:
        current_entropy = (
            shannon_entropy(profile.recent_actions[-cfg.entropy_window:])
            + shannon_entropy(profile.recent_resources[-cfg.entropy_window:])
        ) / 2.0
        if profile.event_count <= 5:
            profile.baseline_entropy = current_entropy
        else:
            profile.baseline_entropy = (
                cfg.baseline_entropy_decay * profile.baseline_entropy
                + (1.0 - cfg.baseline_entropy_decay) * current_entropy
            )

    @staticmethod
    def _update_context_entropy_baseline(ctx: ContextProfile, cfg: SRIAConfig) -> None:
        ctx_entropy = (
            shannon_entropy(ctx.recent_actions[-cfg.entropy_window:])
            + shannon_entropy(ctx.recent_resources[-cfg.entropy_window:])
        ) / 2.0
        if ctx.event_count <= 5:
            ctx.baseline_entropy = ctx_entropy
        else:
            ctx.baseline_entropy = (
                cfg.baseline_entropy_decay * ctx.baseline_entropy
                + (1.0 - cfg.baseline_entropy_decay) * ctx_entropy
            )

    # ----- audit / metrics / persistence -----

    def _append_audit(self, event: Event, decision: Decision) -> None:
        self.audit_log.append({"event": event.to_jsonable(), "decision": decision.to_jsonable()})
        if len(self.audit_log) > self.config.audit_log_limit:
            self.audit_log = self.audit_log[-self.config.audit_log_limit:]

    def export_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return self.metrics.to_jsonable()

    def export_metrics_prometheus(self) -> str:
        metrics = self.export_metrics()
        lines = [
            "# HELP sria_events_total Total evaluated SRIA events",
            "# TYPE sria_events_total counter",
            f"sria_events_total {metrics['total_events']}",
            "# HELP sria_mean_fusion_risk Mean SRIA fusion risk",
            "# TYPE sria_mean_fusion_risk gauge",
            f"sria_mean_fusion_risk {metrics['mean_fusion_risk']}",
            "# HELP sria_mean_confidence Mean SRIA reconstruction confidence",
            "# TYPE sria_mean_confidence gauge",
            f"sria_mean_confidence {metrics['mean_confidence']}",
            "# HELP sria_mean_latency_ms Mean SRIA evaluation latency in milliseconds",
            "# TYPE sria_mean_latency_ms gauge",
            f"sria_mean_latency_ms {metrics['mean_latency_ms']}",
            "# HELP sria_mean_action_cost Mean action friction cost",
            "# TYPE sria_mean_action_cost gauge",
            f"sria_mean_action_cost {metrics['mean_action_cost']}",
        ]
        for action_name, count in metrics["action_counts"].items():
            lines.append(f'sria_action_total{{action="{action_name}"}} {count}')
        for reason, count in metrics["reason_counts"].items():
            lines.append(f'sria_reason_total{{reason="{reason}"}} {count}')
        return "\n".join(lines) + "\n"

    def save_state(self, path: str | Path) -> None:
        with self._lock:
            payload = {
                "version": "sria_lite_v0.6",
                "config": self.config.to_jsonable(),
                "policy": self.policy.to_jsonable(),
                "profiles": {actor: profile.to_jsonable() for actor, profile in self.profiles.items()},
                "context_profiles": {key: profile.to_jsonable() for key, profile in self.context_profiles.items()},
                "graph": self.graph.to_jsonable(),
                "metrics": self.metrics.to_jsonable(),
                "audit_log": self.audit_log[-self.config.audit_log_limit:],
            }
            Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load_state(cls, path: str | Path) -> "SRIALite":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        config = SRIAConfig.from_jsonable(payload.get("config", {}))
        engine = cls(PolicyState.from_jsonable(payload["policy"]), config=config)
        engine.profiles = {
            actor: ActorProfile.from_jsonable(data)
            for actor, data in payload.get("profiles", {}).items()
        }
        engine.context_profiles = {
            key: ContextProfile.from_jsonable(data)
            for key, data in payload.get("context_profiles", {}).items()
        }
        engine.graph = GraphMemory.from_jsonable(payload.get("graph", {}))
        engine.metrics = Metrics.from_jsonable(payload.get("metrics", {}))
        engine.audit_log = list(payload.get("audit_log", []))[-engine.config.audit_log_limit:]
        return engine


# ---------------------------------------------------------------------------
# Event ingestion utilities
# ---------------------------------------------------------------------------


def load_events_json(path: str | Path) -> List[Event]:
    """Load events from a JSON file (list of event objects)."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("events", [])
    return [Event.from_jsonable(item) for item in raw]


def load_events_csv(path: str | Path) -> List[Event]:
    """Load events from a CSV file."""
    text = Path(path).read_text(encoding="utf-8")
    reader = csv.DictReader(io.StringIO(text))
    return [Event.from_csv_row(row) for row in reader]


def load_events(path: str | Path) -> List[Event]:
    """Auto-detect format by extension and load events."""
    p = Path(path)
    if p.suffix.lower() == ".csv":
        return load_events_csv(p)
    return load_events_json(p)


# ---------------------------------------------------------------------------
# Scenario file support
# ---------------------------------------------------------------------------


def load_scenario(path: str | Path) -> Tuple[PolicyState, SRIAConfig, List[Event], List[Event]]:
    """Load a scenario from a JSON file.

    Expected format::

        {
            "policy": { ... PolicyState fields ... },
            "config": { ... SRIAConfig fields ... },       // optional
            "baseline_events": [ ... ],                     // optional warmup events
            "events": [ ... ]                               // events to evaluate
        }
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    policy = PolicyState.from_jsonable(data["policy"])
    config = SRIAConfig.from_jsonable(data["config"]) if "config" in data else SRIAConfig()
    baseline = [Event.from_jsonable(e) for e in data.get("baseline_events", [])]
    events = [Event.from_jsonable(e) for e in data.get("events", [])]
    return policy, config, baseline, events


def run_scenario(path: str | Path) -> Tuple[SRIALite, List[Decision]]:
    """Load and execute a scenario, returning the engine and decisions."""
    policy, config, baseline, events = load_scenario(path)
    engine = SRIALite(policy=policy, config=config)
    for event in baseline:
        engine.evaluate(event)
    decisions = engine.evaluate_batch(events)
    return engine, decisions


# ---------------------------------------------------------------------------
# Synthetic benchmark runner
# ---------------------------------------------------------------------------


class FrequencyBaseline:
    """Trivial frequency-based anomaly baseline for comparison.

    Scores each (actor, action, resource) triple by inverse frequency: rarer
    triples get higher scores.  This is deliberately simple — the point is to
    give SRIA a straw-man comparator, not to be a good detector.
    """

    def __init__(self) -> None:
        self.counts: Dict[Tuple[str, str, str], int] = {}
        self.total: int = 0

    def train(self, events: Iterable[Event]) -> None:
        for event in events:
            key = (event.actor, event.action, event.resource)
            self.counts[key] = self.counts.get(key, 0) + 1
            self.total += 1

    def score(self, event: Event) -> float:
        key = (event.actor, event.action, event.resource)
        freq = self.counts.get(key, 0) / max(1, self.total)
        return clamp01(1.0 - freq)


def generate_synthetic_events(
    policy: PolicyState,
    n_normal: int = 200,
    n_anomalous: int = 50,
    seed: int = 42,
) -> Tuple[List[Event], List[Event]]:
    """Generate labeled synthetic normal and anomalous events.

    Normal events respect policy constraints.  Anomalous events violate at
    least one constraint (role mismatch, frozen resource, missing approval,
    unknown actor, etc.).
    """
    import random
    rng = random.Random(seed)

    roles = list(policy.role_actions.keys())
    all_actions: Set[str] = set()
    for actions in policy.role_actions.values():
        all_actions |= actions
    all_actions_list = sorted(all_actions)

    all_resources: Set[str] = set()
    for resources in policy.role_resources.values():
        all_resources |= resources
    all_resources.discard("*")
    all_resources_list = sorted(all_resources) or ["default_resource"]

    actors_normal = ["user_a", "user_b", "user_c", "user_d"]
    devices = ["laptop_1", "laptop_2", "laptop_3", "laptop_4"]
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    approvals = sorted(policy.active_approvals) or ["APR-1"]

    normal_events: List[Event] = []
    for i in range(n_normal):
        role = rng.choice(roles)
        allowed_actions = sorted(policy.role_actions.get(role, set()))
        if not allowed_actions:
            continue
        action = rng.choice(allowed_actions)
        allowed_resources = sorted(policy.role_resources.get(role, set()))
        if "*" in allowed_resources:
            resource = rng.choice(all_resources_list)
        elif allowed_resources:
            resource = rng.choice(allowed_resources)
        else:
            continue
        actor = rng.choice(actors_normal)
        approval_id = rng.choice(approvals) if action in policy.required_approval_actions else None
        normal_events.append(Event(
            actor=actor,
            role=role,
            action=action,
            resource=resource,
            resource_criticality=round(rng.uniform(0.1, 0.5), 2),
            device_id=rng.choice(devices),
            source_ip=rng.choice(ips),
            approval_id=approval_id,
            label="normal",
        ))

    anomalous_events: List[Event] = []
    anomaly_types = [
        "role_action_mismatch",
        "frozen_resource",
        "missing_approval",
        "unknown_actor",
        "resource_scope_mismatch",
    ]
    for i in range(n_anomalous):
        atype = rng.choice(anomaly_types)
        role = rng.choice(roles)
        actor = rng.choice(actors_normal)
        resource = rng.choice(all_resources_list)
        device = rng.choice(devices)
        ip = rng.choice(ips)
        criticality = round(rng.uniform(0.6, 1.0), 2)

        if atype == "role_action_mismatch":
            allowed = policy.role_actions.get(role, set())
            forbidden = [a for a in all_actions_list if a not in allowed]
            action = rng.choice(forbidden) if forbidden else rng.choice(all_actions_list)
        elif atype == "frozen_resource":
            frozen_list = sorted(policy.frozen_resources)
            resource = rng.choice(frozen_list) if frozen_list else resource
            action = rng.choice(sorted(policy.role_actions.get(role, set())) or all_actions_list)
        elif atype == "missing_approval":
            req = sorted(policy.required_approval_actions)
            action = rng.choice(req) if req else rng.choice(all_actions_list)
        elif atype == "unknown_actor":
            actor = f"intruder_{i}"
            action = rng.choice(all_actions_list)
            device = "unknown_device"
            ip = f"203.0.113.{rng.randint(1, 254)}"
        else:
            allowed_res = policy.role_resources.get(role, set())
            out_of_scope = [r for r in all_resources_list if r not in allowed_res and "*" not in allowed_res]
            resource = rng.choice(out_of_scope) if out_of_scope else resource
            action = rng.choice(sorted(policy.role_actions.get(role, set())) or all_actions_list)

        anomalous_events.append(Event(
            actor=actor,
            role=role,
            action=action,
            resource=resource,
            resource_criticality=criticality,
            device_id=device,
            source_ip=ip,
            label="anomalous",
        ))

    return normal_events, anomalous_events


def run_benchmark(
    policy: PolicyState,
    config: Optional[SRIAConfig] = None,
    n_normal: int = 200,
    n_anomalous: int = 50,
    seed: int = 42,
    include_baseline: bool = True,
) -> Dict[str, Any]:
    """Run a synthetic benchmark and return detection metrics.

    Returns AUC (approximate via trapezoidal rule on sorted thresholds),
    true-positive rate, false-positive rate, and action-distribution stats
    for both SRIA and the optional frequency baseline.
    """
    normal_events, anomalous_events = generate_synthetic_events(policy, n_normal, n_anomalous, seed)

    # Train phase: warm SRIA and baseline on normal events.
    cfg = config or SRIAConfig()
    engine = SRIALite(policy=policy, config=cfg)
    for event in normal_events:
        engine.evaluate(event)

    baseline = FrequencyBaseline()
    if include_baseline:
        baseline.train(normal_events)

    # Evaluate phase: score all events.
    all_events = normal_events + anomalous_events
    labels = [0] * len(normal_events) + [1] * len(anomalous_events)
    sria_scores: List[float] = []
    baseline_scores: List[float] = []
    sria_decisions: List[Decision] = []

    for event in all_events:
        decision = engine.evaluate(event, learn=False)
        sria_decisions.append(decision)
        sria_scores.append(decision.fusion_risk)
        if include_baseline:
            baseline_scores.append(baseline.score(event))

    def compute_metrics(scores: List[float], labels: List[int], threshold: float = 0.25) -> Dict[str, Any]:
        tp = fp = tn = fn = 0
        for score, label in zip(scores, labels):
            predicted = 1 if score >= threshold else 0
            if predicted == 1 and label == 1:
                tp += 1
            elif predicted == 1 and label == 0:
                fp += 1
            elif predicted == 0 and label == 0:
                tn += 1
            else:
                fn += 1
        tpr = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "tpr": round(tpr, 4), "fpr": round(fpr, 4), "precision": round(precision, 4)}

    def approximate_auc(scores: List[float], labels: List[int]) -> float:
        paired = sorted(zip(scores, labels), key=lambda x: -x[0])
        tp_total = sum(labels)
        fp_total = len(labels) - tp_total
        if tp_total == 0 or fp_total == 0:
            return 0.5
        tp = fp = 0
        auc = 0.0
        prev_fpr = 0.0
        prev_tpr = 0.0
        for score, label in paired:
            if label == 1:
                tp += 1
            else:
                fp += 1
            current_tpr = tp / tp_total
            current_fpr = fp / fp_total
            auc += (current_fpr - prev_fpr) * (current_tpr + prev_tpr) / 2.0
            prev_fpr = current_fpr
            prev_tpr = current_tpr
        return round(auc, 4)

    result: Dict[str, Any] = {
        "n_normal": len(normal_events),
        "n_anomalous": len(anomalous_events),
        "sria": {
            "auc": approximate_auc(sria_scores, labels),
            "metrics_at_0.25": compute_metrics(sria_scores, labels, 0.25),
            "metrics_at_0.50": compute_metrics(sria_scores, labels, 0.50),
            "engine_metrics": engine.export_metrics(),
        },
    }
    if include_baseline:
        result["frequency_baseline"] = {
            "auc": approximate_auc(baseline_scores, labels),
            "metrics_at_0.25": compute_metrics(baseline_scores, labels, 0.25),
            "metrics_at_0.50": compute_metrics(baseline_scores, labels, 0.50),
        }
    return result


# ---------------------------------------------------------------------------
# Demo helpers (used by demo_sria_lite.py and __main__)
# ---------------------------------------------------------------------------


def build_demo_engine() -> SRIALite:
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
        active_approvals={"APPROVAL-123"},
        active_delegations={"DEL-OK"},
    )
    sria = SRIALite(policy)
    baseline_events = [
        Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="alice", role="analyst", action="export", resource="reports", approval_id="APPROVAL-123", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", device_id="laptop_2", source_ip="10.0.0.3"),
    ]
    for event in baseline_events:
        sria.evaluate(event)
    return sria


def demo() -> None:
    sria = build_demo_engine()
    test_events = [
        Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="alice", role="analyst", action="delete", resource="reports", resource_criticality=0.7, device_id="laptop_1", source_ip="10.0.0.2"),
        Event(actor="bob", role="engineer", action="deploy", resource="service_b", resource_criticality=0.9, approval_id="APPROVAL-123", mission_state=MissionState.FREEZE, device_id="laptop_2", source_ip="10.0.0.3"),
        Event(actor="carol", role="admin", action="grant_admin", resource="identity", resource_criticality=1.0, device_id="unknown", source_ip="203.0.113.10"),
        Event(actor="bob", role="engineer", action="read", resource="service_a", resource_criticality=0.6, device_id="new_device", source_ip="10.0.0.99"),
    ]
    for i, event in enumerate(test_events, 1):
        decision = sria.evaluate(event)
        print(f"\n--- Event {i} ---")
        print(f"  actor={event.actor} role={event.role} action={event.action} resource={event.resource}")
        print(f"  Action: {decision.action.value} (cost={decision.action_cost:.2f})")
        print(
            f"  Scores: semantic={decision.semantic_risk} behavioral={decision.behavioral_risk} "
            f"graph={decision.graph_risk} provenance={decision.provenance_risk} "
            f"fusion={decision.fusion_risk} confidence={decision.confidence} uncertainty={decision.uncertainty}"
        )
        print(f"  Codes: {[code.value for code in decision.reason_codes]}")
        print("  Reasons:")
        for reason in decision.reasons:
            print(f"    - {reason}")
    print("\n--- Metrics JSON ---")
    print(json.dumps(sria.export_metrics(), indent=2))
    print("\n--- Metrics Prometheus ---")
    print(sria.export_metrics_prometheus())


if __name__ == "__main__":
    demo()
