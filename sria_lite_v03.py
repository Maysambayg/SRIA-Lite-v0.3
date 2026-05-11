"""
SRIA Lite v0.3
Semantic Reconstruction Integrity Architecture - compact defensive decision-governance prototype.

Purpose:
- Evaluate whether an event is semantically valid in context.
- Estimate lightweight behavioral risk from actor and actor-context history.
- Track graph novelty and rolling suspicion with configurable decay.
- Fuse semantic, behavioral, and graph risk with reconstruction confidence gating.
- Map risk into proportional defensive actions.
- Persist/load lightweight state for research experiments.
- Export basic operational metrics for demos and validation.

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
import json
import math
import time


# -----------------------------
# Utilities
# -----------------------------


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


# -----------------------------
# Action ladder, states, reason codes
# -----------------------------


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


@dataclass
class SRIAConfig:
    """Tunable knobs moved out of hard-coded logic."""

    alpha_semantic: float = 0.45
    beta_behavioral: float = 0.30
    gamma_agreement: float = 0.10
    delta_graph: float = 0.15

    suspicion_decay: float = 0.85
    profile_risk_decay: float = 0.90
    baseline_entropy_decay: float = 0.97
    history_window: int = 50
    entropy_window: int = 20
    entropy_shift_threshold: float = 0.35
    context_entropy_shift_threshold: float = 0.30

    graph_novelty_threshold: float = 0.45
    shadow_fusion_min: float = 0.25
    shadow_fusion_max: float = 0.45
    step_up_fusion_threshold: float = 0.30
    queue_review_threshold: float = 0.50
    human_review_threshold: float = 0.70
    high_criticality_threshold: float = 0.80

    audit_log_limit: int = 1000

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        total = self.alpha_semantic + self.beta_behavioral + self.gamma_agreement + self.delta_graph
        if not math.isclose(total, 1.0, abs_tol=1e-9):
            raise ValueError(f"Fusion weights must sum to 1.0, got {total:.6f}")
        for name in [
            "suspicion_decay",
            "profile_risk_decay",
            "baseline_entropy_decay",
            "entropy_shift_threshold",
            "context_entropy_shift_threshold",
            "graph_novelty_threshold",
            "shadow_fusion_min",
            "shadow_fusion_max",
            "step_up_fusion_threshold",
            "queue_review_threshold",
            "human_review_threshold",
            "high_criticality_threshold",
        ]:
            val = getattr(self, name)
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


@dataclass
class Event:
    actor: str
    role: str
    action: str
    resource: str
    resource_criticality: float = 0.5  # 0.0 low, 1.0 high
    timestamp: float = field(default_factory=time.time)
    approval_id: Optional[str] = None
    delegation_id: Optional[str] = None
    mission_state: MissionState | str = MissionState.NORMAL
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    source_ip: Optional[str] = None

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
        }


@dataclass
class PolicyState:
    role_actions: Dict[str, Set[str]]
    role_resources: Dict[str, Set[str]]
    frozen_resources: Set[str] = field(default_factory=set)
    required_approval_actions: Set[str] = field(default_factory=lambda: {"deploy", "delete", "export", "grant_admin"})
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

    def graph_risk(self, event: Event) -> Tuple[float, List[Reason]]:
        novelty = 0.0
        reasons: List[Reason] = []
        if (event.actor, event.resource) not in self.actor_resource_edges:
            novelty += 0.35
            reasons.append(Reason(ReasonCode.GRAPH_NOVELTY, f"new actor-resource edge: '{event.actor}' -> '{event.resource}'", 0.35))
        if (event.actor, event.action) not in self.actor_action_edges:
            novelty += 0.25
            reasons.append(Reason(ReasonCode.GRAPH_NOVELTY, f"new actor-action edge: '{event.actor}' -> '{event.action}'", 0.25))
        if (event.role, event.action) not in self.role_action_edges:
            novelty += 0.20
            reasons.append(Reason(ReasonCode.GRAPH_NOVELTY, f"new role-action edge: '{event.role}' -> '{event.action}'", 0.20))
        memory = self.suspicion_by_actor.get(event.actor, 0.0) * 0.25
        if memory > 0.10:
            reasons.append(Reason(ReasonCode.GRAPH_SUSPICION_MEMORY, f"rolling actor suspicion memory: {memory:.3f}", memory))
        return clamp01(novelty + memory), reasons

    def update(self, event: Event, risk: float, suspicion_decay: float) -> None:
        self.actor_resource_edges[(event.actor, event.resource)] = self.actor_resource_edges.get((event.actor, event.resource), 0) + 1
        self.actor_action_edges[(event.actor, event.action)] = self.actor_action_edges.get((event.actor, event.action), 0) + 1
        self.role_action_edges[(event.role, event.action)] = self.role_action_edges.get((event.role, event.action), 0) + 1
        old = self.suspicion_by_actor.get(event.actor, 0.0)
        self.suspicion_by_actor[event.actor] = clamp01(suspicion_decay * old + (1.0 - suspicion_decay) * risk)

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
    semantic_risk: float
    behavioral_risk: float
    graph_risk: float
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
            "semantic_risk": self.semantic_risk,
            "behavioral_risk": self.behavioral_risk,
            "graph_risk": self.graph_risk,
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
    max_fusion_risk: float = 0.0

    def record(self, decision: Decision) -> None:
        self.total_events += 1
        self.action_counts[decision.action.value] = self.action_counts.get(decision.action.value, 0) + 1
        for code in decision.reason_codes:
            self.reason_counts[code.value] = self.reason_counts.get(code.value, 0) + 1
        self.risk_sum += decision.fusion_risk
        self.confidence_sum += decision.confidence
        self.latency_ms_sum += decision.latency_ms
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
            "max_fusion_risk": round(self.max_fusion_risk, 6),
        }

    @classmethod
    def from_jsonable(cls, data: Dict[str, Any]) -> "Metrics":
        m = cls()
        m.total_events = int(data.get("total_events", 0))
        m.action_counts = {k: int(v) for k, v in data.get("action_counts", {}).items()}
        m.reason_counts = {k: int(v) for k, v in data.get("reason_counts", {}).items()}
        # Averages cannot reconstruct sums exactly. Keep state fresh after load.
        return m


# -----------------------------
# SRIA Lite Engine
# -----------------------------


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

    def evaluate(self, event: Event, learn: bool = True) -> Decision:
        start = time.perf_counter()
        with self._lock:
            semantic_risk, semantic_reasons = self.semantic_integrity_spine(event)
            behavioral_risk, behavioral_reasons, entropy = self.learned_behavioral_companion_lite(event)
            graph_risk, graph_reasons = self.graph.graph_risk(event)
            confidence = self.confidence_gate(semantic_risk, behavioral_risk, graph_risk)
            fusion_risk = self.fuse(semantic_risk, behavioral_risk, graph_risk, confidence)
            all_reasons = semantic_reasons + behavioral_reasons + graph_reasons
            action = self.action_specific_governor(event, semantic_risk, behavioral_risk, graph_risk, fusion_risk, confidence, all_reasons)

            if learn:
                self.update_memory(event, fusion_risk)

            if not all_reasons:
                all_reasons = [Reason(ReasonCode.NO_ISSUE, "no material reconstruction-integrity issue detected")]

            latency_ms = (time.perf_counter() - start) * 1000.0
            decision = Decision(
                action=action,
                semantic_risk=round(semantic_risk, 3),
                behavioral_risk=round(behavioral_risk, 3),
                graph_risk=round(graph_risk, 3),
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

    def semantic_integrity_spine(self, event: Event) -> Tuple[float, List[Reason]]:
        risk = 0.0
        reasons: List[Reason] = []
        if event.role not in self.policy.role_actions:
            risk += 0.25
            reasons.append(Reason(ReasonCode.ROLE_UNKNOWN, f"unknown role: '{event.role}'", 0.25))

        allowed_actions = self.policy.role_actions.get(event.role, set())
        if event.action not in allowed_actions:
            risk += 0.35
            reasons.append(Reason(ReasonCode.ROLE_ACTION_MISMATCH, f"role/action mismatch: role '{event.role}' is not allowed to perform '{event.action}'", 0.35))

        allowed_resources = self.policy.role_resources.get(event.role, set())
        if "*" not in allowed_resources and event.resource not in allowed_resources:
            risk += 0.30
            reasons.append(Reason(ReasonCode.RESOURCE_SCOPE_MISMATCH, f"resource-scope mismatch: role '{event.role}' is not scoped to '{event.resource}'", 0.30))

        if event.resource in self.policy.frozen_resources:
            risk += 0.55
            reasons.append(Reason(ReasonCode.RESOURCE_FROZEN, f"mission/freeze violation: resource '{event.resource}' is frozen", 0.55))

        if event.action in self.policy.required_approval_actions:
            if not event.approval_id or event.approval_id not in self.policy.active_approvals:
                risk += 0.30
                reasons.append(Reason(ReasonCode.MISSING_OR_INVALID_APPROVAL, f"missing or invalid approval for sensitive action '{event.action}'", 0.30))

        if event.delegation_id and event.delegation_id not in self.policy.active_delegations:
            risk += 0.25
            reasons.append(Reason(ReasonCode.INVALID_DELEGATION, f"invalid delegation lifecycle: delegation '{event.delegation_id}' is not active", 0.25))

        mission_state = event.normalized_mission_state()
        if mission_state == MissionState.FREEZE and event.action not in {"read", "audit", "reverify"}:
            risk += 0.45
            reasons.append(Reason(ReasonCode.MISSION_STATE_CONTRADICTION, "mission-state contradiction: non-read action during freeze state", 0.45))
        return clamp01(risk), reasons

    def learned_behavioral_companion_lite(self, event: Event) -> Tuple[float, List[Reason], float]:
        profile = self.profiles.get(event.actor)
        if profile is None or profile.event_count == 0:
            return 0.15, [Reason(ReasonCode.LOW_HISTORY_ACTOR, "new or low-history actor: limited behavioral baseline", 0.15)], 0.0

        risk = 0.0
        reasons: List[Reason] = []
        if event.role not in profile.known_roles:
            risk += 0.20
            reasons.append(Reason(ReasonCode.ACTOR_ROLE_NOVELTY, f"actor-role novelty: '{event.actor}' rarely/never used role '{event.role}'", 0.20))
        if event.action not in profile.known_actions:
            risk += 0.20
            reasons.append(Reason(ReasonCode.ACTOR_ACTION_NOVELTY, f"actor-action novelty: '{event.actor}' rarely/never performed '{event.action}'", 0.20))
        if event.resource not in profile.known_resources:
            r = 0.20 * (0.5 + clamp01(event.resource_criticality))
            risk += r
            reasons.append(Reason(ReasonCode.ACTOR_RESOURCE_NOVELTY, f"actor-resource novelty: '{event.actor}' rarely/never accessed '{event.resource}'", r))
        if event.device_id and profile.known_devices and event.device_id not in profile.known_devices:
            risk += 0.20
            reasons.append(Reason(ReasonCode.NEW_DEVICE, f"identity-continuity concern: new device '{event.device_id}'", 0.20))
        if event.source_ip and profile.known_ips and event.source_ip not in profile.known_ips:
            risk += 0.15
            reasons.append(Reason(ReasonCode.NEW_SOURCE_IP, f"identity-continuity concern: new source IP '{event.source_ip}'", 0.15))

        cfg = self.config
        candidate_actions = (profile.recent_actions + [event.action])[-cfg.entropy_window:]
        candidate_resources = (profile.recent_resources + [event.resource])[-cfg.entropy_window:]
        entropy = (shannon_entropy(candidate_actions) + shannon_entropy(candidate_resources)) / 2.0
        if profile.event_count >= 5:
            shift = max(0.0, entropy - profile.baseline_entropy)
            if shift > cfg.entropy_shift_threshold:
                add = min(0.15, 0.30 * shift)
                risk += add
                reasons.append(Reason(ReasonCode.BEHAVIORAL_ENTROPY_SHIFT, f"actor entropy shift: current={entropy:.3f}, baseline={profile.baseline_entropy:.3f}", add))

        ctx = self.context_profiles.get(event.context_key())
        if ctx and ctx.event_count >= 5:
            ctx_actions = (ctx.recent_actions + [event.action])[-cfg.entropy_window:]
            ctx_resources = (ctx.recent_resources + [event.resource])[-cfg.entropy_window:]
            ctx_entropy = (shannon_entropy(ctx_actions) + shannon_entropy(ctx_resources)) / 2.0
            ctx_shift = max(0.0, ctx_entropy - ctx.baseline_entropy)
            if ctx_shift > cfg.context_entropy_shift_threshold:
                add = min(0.12, 0.25 * ctx_shift)
                risk += add
                reasons.append(Reason(ReasonCode.CONTEXT_ENTROPY_SHIFT, f"actor-context entropy shift: current={ctx_entropy:.3f}, baseline={ctx.baseline_entropy:.3f}", add))

        risk += 0.25 * profile.recent_risk
        return clamp01(risk), reasons, entropy

    def confidence_gate(self, semantic_risk: float, behavioral_risk: float, graph_risk: float) -> float:
        agreement = 1.0 - (max(semantic_risk, behavioral_risk, graph_risk) - min(semantic_risk, behavioral_risk, graph_risk))
        low_risk_strength = 1.0 - max(semantic_risk, behavioral_risk, graph_risk)
        support = 1.0 - abs(semantic_risk - behavioral_risk)
        return clamp01(0.45 * agreement + 0.40 * low_risk_strength + 0.15 * support)

    def fuse(self, semantic_risk: float, behavioral_risk: float, graph_risk: float, confidence: float) -> float:
        cfg = self.config
        interaction = min(semantic_risk, behavioral_risk) * confidence
        gated_graph = graph_risk * confidence
        raw = cfg.alpha_semantic * semantic_risk + cfg.beta_behavioral * behavioral_risk + cfg.gamma_agreement * interaction + cfg.delta_graph * gated_graph
        return clamp01(raw)

    def action_specific_governor(self, event: Event, semantic_risk: float, behavioral_risk: float, graph_risk: float, fusion_risk: float, confidence: float, reasons: List[Reason]) -> Action:
        cfg = self.config
        codes = {reason.code for reason in reasons}
        if ReasonCode.RESOURCE_FROZEN in codes or ReasonCode.MISSION_STATE_CONTRADICTION in codes:
            if semantic_risk >= 0.85 or event.resource_criticality >= cfg.high_criticality_threshold:
                return Action.BLOCK
            return Action.HUMAN_REVIEW
        if ReasonCode.ROLE_ACTION_MISMATCH in codes and semantic_risk >= 0.65:
            return Action.HUMAN_REVIEW
        if ReasonCode.RESOURCE_SCOPE_MISMATCH in codes and event.resource_criticality >= cfg.high_criticality_threshold:
            return Action.HUMAN_REVIEW if semantic_risk >= 0.45 else Action.QUEUE_REVIEW
        if ReasonCode.INVALID_DELEGATION in codes or ReasonCode.MISSING_OR_INVALID_APPROVAL in codes:
            if semantic_risk >= 0.60 and event.resource_criticality >= 0.7:
                return Action.HUMAN_REVIEW
            return Action.QUEUE_REVIEW
        if ReasonCode.NEW_DEVICE in codes or ReasonCode.NEW_SOURCE_IP in codes:
            return Action.SESSION_REVERIFY
        if ReasonCode.ACTOR_ROLE_NOVELTY in codes or ReasonCode.ACTOR_ACTION_NOVELTY in codes:
            return Action.STEP_UP_AUTH if fusion_risk >= cfg.step_up_fusion_threshold else Action.WATCH
        if graph_risk >= cfg.graph_novelty_threshold or (cfg.shadow_fusion_min <= fusion_risk < cfg.shadow_fusion_max):
            return Action.SHADOW_OBSERVE
        if behavioral_risk >= 0.45 and semantic_risk < 0.30:
            return Action.COLLECT_EVIDENCE
        if fusion_risk >= cfg.human_review_threshold and confidence <= 0.60:
            return Action.HUMAN_REVIEW
        if fusion_risk >= cfg.queue_review_threshold:
            return Action.QUEUE_REVIEW
        if fusion_risk >= cfg.shadow_fusion_min:
            return Action.WATCH
        return Action.ALLOW

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
        current_entropy = (shannon_entropy(profile.recent_actions[-cfg.entropy_window:]) + shannon_entropy(profile.recent_resources[-cfg.entropy_window:])) / 2.0
        if profile.event_count <= 5:
            profile.baseline_entropy = current_entropy
        else:
            profile.baseline_entropy = cfg.baseline_entropy_decay * profile.baseline_entropy + (1.0 - cfg.baseline_entropy_decay) * current_entropy
        profile.recent_risk = clamp01(cfg.profile_risk_decay * profile.recent_risk + (1.0 - cfg.profile_risk_decay) * risk)

        ctx = self.context_profiles.setdefault(event.context_key(), ContextProfile())
        ctx.recent_actions.append(event.action)
        ctx.recent_resources.append(event.resource)
        ctx.recent_actions = ctx.recent_actions[-cfg.history_window:]
        ctx.recent_resources = ctx.recent_resources[-cfg.history_window:]
        ctx.event_count += 1
        ctx_entropy = (shannon_entropy(ctx.recent_actions[-cfg.entropy_window:]) + shannon_entropy(ctx.recent_resources[-cfg.entropy_window:])) / 2.0
        if ctx.event_count <= 5:
            ctx.baseline_entropy = ctx_entropy
        else:
            ctx.baseline_entropy = cfg.baseline_entropy_decay * ctx.baseline_entropy + (1.0 - cfg.baseline_entropy_decay) * ctx_entropy

        self.graph.update(event, risk, cfg.suspicion_decay)

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
        ]
        for action, count in metrics["action_counts"].items():
            lines.append(f'sria_action_total{{action="{action}"}} {count}')
        for reason, count in metrics["reason_counts"].items():
            lines.append(f'sria_reason_total{{reason="{reason}"}} {count}')
        return "\n".join(lines) + "\n"

    def save_state(self, path: str | Path) -> None:
        with self._lock:
            payload = {
                "version": "sria_lite_v0.3",
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
        engine.profiles = {actor: ActorProfile.from_jsonable(data) for actor, data in payload.get("profiles", {}).items()}
        engine.context_profiles = {key: ContextProfile.from_jsonable(data) for key, data in payload.get("context_profiles", {}).items()}
        engine.graph = GraphMemory.from_jsonable(payload.get("graph", {}))
        engine.metrics = Metrics.from_jsonable(payload.get("metrics", {}))
        engine.audit_log = list(payload.get("audit_log", []))[-engine.config.audit_log_limit:]
        return engine


# -----------------------------
# Demo and tests
# -----------------------------


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
        print(event)
        print(f"Action: {decision.action.value}")
        print(
            f"Scores: semantic={decision.semantic_risk}, behavioral={decision.behavioral_risk}, graph={decision.graph_risk}, "
            f"fusion={decision.fusion_risk}, confidence={decision.confidence}, uncertainty={decision.uncertainty}, "
            f"entropy={decision.entropy}, latency_ms={decision.latency_ms}"
        )
        print(f"Codes: {[code.value for code in decision.reason_codes]}")
        print("Reasons:")
        for reason in decision.reasons:
            print(f"  - {reason}")
    print("\n--- Metrics JSON ---")
    print(json.dumps(sria.export_metrics(), indent=2))
    print("\n--- Metrics Prometheus ---")
    print(sria.export_metrics_prometheus())


def run_tests() -> None:
    sria = build_demo_engine()
    assert math.isclose(
        sria.config.alpha_semantic + sria.config.beta_behavioral + sria.config.gamma_agreement + sria.config.delta_graph,
        1.0,
        abs_tol=1e-9,
    )
    low_conf = sria.confidence_gate(0.0, 0.0, 0.0)
    high_conf = sria.confidence_gate(0.9, 0.9, 0.9)
    assert low_conf > high_conf, (low_conf, high_conf)
    fused = sria.fuse(1.0, 1.0, 1.0, confidence=1.0)
    assert math.isclose(fused, 1.0, abs_tol=1e-9), fused
    normal = sria.evaluate(Event(actor="alice", role="analyst", action="read", resource="reports", device_id="laptop_1", source_ip="10.0.0.2"), learn=False)
    assert normal.action == Action.ALLOW, normal
    assert ReasonCode.NO_ISSUE in normal.reason_codes, normal.reason_codes
    unauthorized = sria.evaluate(Event(actor="alice", role="analyst", action="delete", resource="reports", resource_criticality=0.7), learn=False)
    assert unauthorized.action in {Action.HUMAN_REVIEW, Action.QUEUE_REVIEW}, unauthorized
    assert ReasonCode.ROLE_ACTION_MISMATCH in unauthorized.reason_codes, unauthorized.reason_codes
    frozen = sria.evaluate(Event(actor="bob", role="engineer", action="deploy", resource="service_b", resource_criticality=0.9, approval_id="APPROVAL-123", mission_state=MissionState.FREEZE), learn=False)
    assert frozen.action == Action.BLOCK, frozen
    assert ReasonCode.RESOURCE_FROZEN in frozen.reason_codes, frozen.reason_codes
    # Config validation catches old bug class.
    try:
        SRIAConfig(alpha_semantic=0.5, beta_behavioral=0.35, gamma_agreement=0.15, delta_graph=0.20)
        raise AssertionError("bad config should have failed")
    except ValueError:
        pass
    # Persistence round trip, including config/context profiles/audit.
    tmp = Path("/tmp/sria_lite_state_v03_test.json")
    sria.save_state(tmp)
    loaded = SRIALite.load_state(tmp)
    assert set(loaded.profiles.keys()) == set(sria.profiles.keys())
    assert loaded.graph.actor_action_edges == sria.graph.actor_action_edges
    assert loaded.config.suspicion_decay == sria.config.suspicion_decay
    assert loaded.context_profiles.keys() == sria.context_profiles.keys()
    # Metrics export exists and is Prometheus-shaped.
    sria.evaluate(Event(actor="alice", role="analyst", action="read", resource="reports"), learn=False)
    metrics = sria.export_metrics()
    assert metrics["total_events"] >= 1
    prom = sria.export_metrics_prometheus()
    assert "sria_events_total" in prom and "sria_mean_fusion_risk" in prom


if __name__ == "__main__":
    run_tests()
    demo()
