#!/usr/bin/env python3
"""
SRIA LANL Processor v0.6

Correlation Quality Gate + Episode Compression

Purpose:
- Keep the scalable v0.5.2 processing model.
- Stop treating all host/network correlations as equally meaningful.
- Downgrade large_outbound-only correlation.
- Prioritize suspicious_port, DNS, suspicious_process, explicit_credential, failed_logon, and human-user context.
- Compress repeated high-signal events from the same host into short episodes.

Outputs:
    suspicious_events_v06.jsonl
    correlation_events_v06.jsonl
    high_signal_episodes_v06.jsonl
    sria_v06_report.txt

Run:
    py sria_v06.py --self-test
    py sria_v06.py --max-events 100000
    py sria_v06.py --max-events 1000000
    py sria_v06.py
"""

from __future__ import annotations

import argparse
import bisect
import json
import tempfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple


# ============================================================
# DEFAULT PATHS
# ============================================================

DEFAULT_NETWORK_FILE = r"F:\SRIA\netflow_day-90.csv"
DEFAULT_HOST_FILE = r"F:\SRIA\wls_day-90.json"
DEFAULT_SUSPICIOUS_FILE = r"F:\SRIA\suspicious_events_v06.jsonl"
DEFAULT_CORRELATION_FILE = r"F:\SRIA\correlation_events_v06.jsonl"
DEFAULT_EPISODE_FILE = r"F:\SRIA\high_signal_episodes_v06.jsonl"
DEFAULT_REPORT_FILE = r"F:\SRIA\sria_v06_report.txt"


@dataclass
class ProcessorConfig:
    network_file: Path = Path(DEFAULT_NETWORK_FILE)
    host_file: Path = Path(DEFAULT_HOST_FILE)
    suspicious_file: Path = Path(DEFAULT_SUSPICIOUS_FILE)
    correlation_file: Path = Path(DEFAULT_CORRELATION_FILE)
    episode_file: Path = Path(DEFAULT_EPISODE_FILE)
    report_file: Path = Path(DEFAULT_REPORT_FILE)

    max_events: int = 0
    progress_every: int = 1_000_000

    # Network thresholds
    normal_dns_threshold: int = 100
    normal_dns_window_sec: int = 60
    normal_large_transfer_bytes: int = 100_000
    normal_watch_ports: set[int] = field(default_factory=lambda: {4444, 5555, 6666, 7777, 8888, 9999})

    infra_dns_threshold: int = 500
    infra_dns_window_sec: int = 60
    infra_large_transfer_bytes: int = 1_000_000
    infra_watch_ports: set[int] = field(default_factory=set)

    # Correlation
    correlation_window_sec: int = 300
    max_network_events_per_key: int = 5000

    # Episode compression
    episode_window_sec: int = 300
    episode_min_quality: float = 0.25


# ============================================================
# CLASSIFICATION + RULE TABLES
# ============================================================

INFRASTRUCTURE_RESOURCES = {
    "Comp275646", "Comp387111", "ActiveDirectory", "Mail", "VPN",
    "EnterpriseAppServer", "DNS", "Gateway", "Proxy",
}
INFRASTRUCTURE_ACTORS = {
    "VPN", "system", "SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE",
    "ActiveDirectory$", "EnterpriseAppServer$",
}
SERVICE_ACCOUNT_PREFIXES = ("svc", "appservice", "service")

HOST_BASE_RISKS = {
    4624: 0.05,  # logon success
    4625: 0.60,  # failed logon
    4634: 0.00,  # logoff
    4648: 0.35,  # explicit credential use
    4672: 0.15,  # special privileges, calibrated down
    4688: 0.10,  # process start
    4768: 0.05,
    4769: 0.05,
    4776: 0.30,  # credential validation
}

SUSPICIOUS_PROCESSES = {
    "cmd.exe": 0.40,
    "powershell.exe": 0.50,
    "cscript.exe": 0.60,
    "wscript.exe": 0.60,
    "rundll32.exe": 0.40,
    "regsvr32.exe": 0.50,
    "mshta.exe": 0.50,
    "wmic.exe": 0.40,
    "net.exe": 0.30,
    "net1.exe": 0.30,
}

NOISY_PROCESSES = {
    "taskeng.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe",
    "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "spoolsv.exe",
}


def classify_actor(actor: str) -> str:
    if not actor:
        return "unknown"
    low = actor.lower()
    if low in {"system", "nt authority\\system", "local service", "network service"}:
        return "system_account"
    if actor in INFRASTRUCTURE_ACTORS:
        return "infrastructure_account"
    if any(low.startswith(prefix) for prefix in SERVICE_ACCOUNT_PREFIXES):
        return "service_account"
    if actor.endswith("$"):
        return "computer_account"
    if low.startswith("user"):
        return "human_user"
    return "human_user"


def is_infrastructure(actor: Optional[str] = None, resource: Optional[str] = None) -> bool:
    return bool((actor and actor in INFRASTRUCTURE_ACTORS) or (resource and resource in INFRASTRUCTURE_RESOURCES))


def host_key_from_network(event: Dict[str, Any]) -> str:
    return str(event.get("actor") or "unknown")


def host_key_from_host(event: Dict[str, Any]) -> str:
    return str(event.get("resource") or "unknown")


# ============================================================
# PARSERS
# ============================================================

def parse_network_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.strip().split(",")
    if len(parts) < 11:
        return None
    try:
        src_port = parts[5].replace("Port", "")
        dst_port = parts[6].replace("Port", "")
        return {
            "type": "network",
            "timestamp": int(parts[0]),
            "actor": parts[2],
            "resource": parts[3],
            "protocol": parts[4],
            "src_port": int(src_port) if src_port.isdigit() else 0,
            "dst_port": int(dst_port) if dst_port.isdigit() else 0,
            "src_packets": int(parts[7]),
            "dst_packets": int(parts[8]),
            "src_bytes": int(parts[9]),
            "dst_bytes": int(parts[10]),
        }
    except Exception:
        return None


def parse_host_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(line.strip())
        resource = data.get("Computer", data.get("LogHost", "unknown"))
        return {
            "type": "host",
            "timestamp": int(data.get("Time", 0) or 0),
            "actor": data.get("UserName", "unknown"),
            "resource": resource,
            "event_id": data.get("EventID"),
            "process_name": data.get("ProcessName", ""),
            "parent_process_name": data.get("ParentProcessName", ""),
            "status": data.get("Status"),
            "logon_id": data.get("LogonID"),
            "source": data.get("Source"),
            "destination": data.get("Destination"),
            "logon_type": data.get("LogonType"),
            "authentication_package": data.get("AuthenticationPackage"),
        }
    except Exception:
        return None


# ============================================================
# DNS + NETWORK INDEX
# ============================================================

class TimeWindowedDNS:
    def __init__(self) -> None:
        self.queries: Dict[str, Deque[Tuple[int, str]]] = defaultdict(deque)

    def add_query(self, timestamp: int, actor: str, target: str, window_sec: int) -> int:
        cutoff = timestamp - window_sec
        q = self.queries[actor]
        while q and q[0][0] < cutoff:
            q.popleft()
        q.append((timestamp, target))
        return len(q)


class SuspiciousNetworkIndex:
    """
    Indexes only suspicious network events.

    Categories:
      suspicious_port = strong
      dns_flood       = medium
      large_outbound  = weak unless paired with host evidence
    """

    def __init__(self, max_per_key: int = 5000) -> None:
        self.max_per_key = max_per_key
        self.by_actor: Dict[str, List[Tuple[int, float, str]]] = defaultdict(list)
        self.by_host: Dict[str, List[Tuple[int, float, str]]] = defaultdict(list)
        self.total_indexed = 0
        self.cap_drops = 0

    def add(self, actor: str, host_key: str, timestamp: int, risk: float, category: str) -> None:
        item = (timestamp, risk, category)
        self._append(self.by_actor[actor], item)
        self._append(self.by_host[host_key], item)
        self.total_indexed += 1

    def _append(self, items: List[Tuple[int, float, str]], item: Tuple[int, float, str]) -> None:
        items.append(item)
        if len(items) > self.max_per_key:
            del items[: len(items) - self.max_per_key]
            self.cap_drops += 1

    @staticmethod
    def _best_in_window(items: List[Tuple[int, float, str]], ts: int, window: int) -> Optional[Tuple[int, float, str]]:
        if not items:
            return None
        lo, hi = ts - window, ts + window
        left = bisect.bisect_left(items, (lo, -1.0, ""))
        right = bisect.bisect_right(items, (hi, 2.0, "zzzz"))
        if left >= right:
            return None
        best = None
        for item in items[left:right]:
            if best is None or NETWORK_CATEGORY_STRENGTH.get(item[2], 0) > NETWORK_CATEGORY_STRENGTH.get(best[2], 0):
                best = item
            elif best is not None and item[2] == best[2] and item[1] > best[1]:
                best = item
        return best

    def check(self, actor: str, host_key: str, ts: int, window: int) -> List[Tuple[str, str, float]]:
        matches = []
        actor_match = self._best_in_window(self.by_actor.get(actor, []), ts, window)
        if actor_match:
            _, risk, cat = actor_match
            matches.append(("actor", cat, risk))
        host_match = self._best_in_window(self.by_host.get(host_key, []), ts, window)
        if host_match:
            _, risk, cat = host_match
            matches.append(("hostkey", cat, risk))
        return matches


NETWORK_CATEGORY_STRENGTH = {
    "large_outbound": 1,
    "dns_flood": 2,
    "suspicious_port": 3,
}


# ============================================================
# REASON + ACTION HELPERS
# ============================================================

def action_from_network_risk(risk: float) -> str:
    if risk >= 0.7:
        return "BLOCK"
    if risk >= 0.4:
        return "COLLECT_EVIDENCE"
    if risk >= 0.2:
        return "WATCH"
    return "ALLOW"


def action_from_host_risk(risk: float) -> str:
    if risk >= 0.7:
        return "HUMAN_REVIEW"
    if risk >= 0.4:
        return "COLLECT_EVIDENCE"
    if risk >= 0.2:
        return "WATCH"
    return "ALLOW"


def normalize_reason(reason: str) -> str:
    if reason.startswith("dns_flood"):
        return "dns_flood"
    if reason.startswith("large_outbound"):
        return "large_outbound"
    if reason.startswith("suspicious_port"):
        return "suspicious_port"
    if reason.startswith("suspicious_process"):
        return "suspicious_process"
    if reason.startswith("explicit_credential"):
        return "explicit_credential"
    if reason.startswith("special_privileges"):
        return "special_privileges"
    if reason.startswith("failed_logon"):
        return "failed_logon"
    if reason.startswith("credential_validation"):
        return "credential_validation"
    if reason.startswith("noisy_process_suppressed"):
        return "noisy_process_suppressed"
    if reason.startswith("unusual_"):
        return "unusual_parent_process"
    if reason.startswith("quality_"):
        return reason
    if reason.startswith("correlation_"):
        return reason
    if reason == "infrastructure_downgrade":
        return reason
    return reason or "none"


def category_from_network_reasons(reasons: List[str]) -> str:
    text = " ".join(reasons)
    if "suspicious_port" in text:
        return "suspicious_port"
    if "dns_flood" in text:
        return "dns_flood"
    if "large_outbound" in text:
        return "large_outbound"
    return "other"


# ============================================================
# NETWORK EVALUATION
# ============================================================

def evaluate_network(event: Dict[str, Any], config: ProcessorConfig, dns: TimeWindowedDNS) -> Tuple[str, float, List[str], str]:
    actor, resource = event["actor"], event["resource"]
    dst_port, src_bytes, ts = event["dst_port"], event["src_bytes"], event["timestamp"]
    infra = is_infrastructure(actor=actor, resource=resource)

    if infra:
        dns_threshold, dns_window = config.infra_dns_threshold, config.infra_dns_window_sec
        large_threshold, watch_ports = config.infra_large_transfer_bytes, config.infra_watch_ports
    else:
        dns_threshold, dns_window = config.normal_dns_threshold, config.normal_dns_window_sec
        large_threshold, watch_ports = config.normal_large_transfer_bytes, config.normal_watch_ports

    risk = 0.0
    reasons: List[str] = []

    if dst_port in watch_ports:
        risk += 0.60
        reasons.append(f"suspicious_port_{dst_port}")

    if src_bytes > large_threshold:
        risk += 0.30
        reasons.append(f"large_outbound_{src_bytes}")

    if dst_port == 53:
        count = dns.add_query(ts, actor, resource, dns_window)
        if count >= dns_threshold:
            risk += 0.50
            reasons.append(f"dns_flood_{count}_in_{dns_window}s")

    if infra and risk >= 0.7:
        has_dns = any("dns_flood" in r for r in reasons)
        has_large = any("large_outbound" in r for r in reasons)
        has_port = any("suspicious_port" in r for r in reasons)
        if has_dns and has_large and not has_port:
            risk = 0.55
            reasons.append("infrastructure_downgrade")

    risk = min(risk, 1.0)
    return action_from_network_risk(risk), risk, reasons, category_from_network_reasons(reasons)


# ============================================================
# HOST EVALUATION + QUALITY GATE
# ============================================================

def host_evidence_from_reasons(reasons: List[str], account_type: str) -> Dict[str, bool]:
    text = " ".join(reasons)
    return {
        "human_user": account_type == "human_user",
        "suspicious_process": "suspicious_process" in text,
        "explicit_credential": "explicit_credential" in text,
        "failed_logon": "failed_logon" in text,
        "credential_validation": "credential_validation" in text,
        "special_privileges_human": "special_privileges_human" in text,
        "special_privileges_nonhuman": "special_privileges_nonhuman" in text,
        "noisy_process": "noisy_process_suppressed" in text,
        "unusual_parent": "unusual_" in text,
    }


def correlation_quality(match_category: str, evidence: Dict[str, bool], account_type: str) -> Tuple[float, List[str]]:
    """
    Returns quality boost and quality reasons.

    Critical rule:
    large_outbound alone gives no boost.
    """
    reasons: List[str] = []
    boost = 0.0

    strong_host = evidence["suspicious_process"] or evidence["explicit_credential"] or evidence["failed_logon"]
    meaningful_host = strong_host or evidence["credential_validation"] or evidence["special_privileges_human"] or evidence["unusual_parent"]

    if match_category == "suspicious_port":
        boost = 0.35
        reasons.append("quality_strong_suspicious_port")
        if evidence["suspicious_process"]:
            boost += 0.10
            reasons.append("quality_suspicious_process_plus_port")
        if evidence["explicit_credential"]:
            boost += 0.08
            reasons.append("quality_explicit_credential_plus_port")

    elif match_category == "dns_flood":
        boost = 0.15
        reasons.append("quality_medium_dns")
        if strong_host:
            boost += 0.10
            reasons.append("quality_host_signal_plus_dns")

    elif match_category == "large_outbound":
        # No boost by itself.
        if evidence["noisy_process"] and not strong_host:
            boost = 0.0
            reasons.append("quality_large_outbound_noisy_suppressed")
        elif evidence["suspicious_process"]:
            boost = 0.15
            reasons.append("quality_suspicious_process_plus_large_outbound")
        elif evidence["explicit_credential"]:
            boost = 0.12
            reasons.append("quality_explicit_credential_plus_large_outbound")
        elif evidence["failed_logon"]:
            boost = 0.10
            reasons.append("quality_failed_logon_plus_large_outbound")
        elif evidence["human_user"] and meaningful_host:
            boost = 0.06
            reasons.append("quality_human_meaningful_large_outbound")
        else:
            boost = 0.0
            reasons.append("quality_large_outbound_only_no_boost")

    # Account-type dampening
    if account_type in {"computer_account", "system_account", "infrastructure_account"} and match_category == "large_outbound":
        boost *= 0.50
        reasons.append("quality_nonhuman_large_outbound_dampened")

    return min(boost, 0.50), reasons


def evaluate_host(event: Dict[str, Any], config: ProcessorConfig, net_index: SuspiciousNetworkIndex) -> Tuple[str, float, List[str], str, float]:
    actor, ts = event["actor"], event["timestamp"]
    account_type = classify_actor(actor)
    event_id = event.get("event_id")
    proc = (event.get("process_name") or "").lower()
    parent = (event.get("parent_process_name") or "").lower()

    risk = HOST_BASE_RISKS.get(event_id, 0.05)
    reasons: List[str] = []

    if event_id == 4625:
        reasons.append("failed_logon")
    elif event_id == 4648:
        reasons.append("explicit_credential_use")
    elif event_id == 4672:
        if account_type in {"system_account", "computer_account", "infrastructure_account", "service_account"}:
            risk = 0.10
            reasons.append("special_privileges_nonhuman_downgrade")
        else:
            risk = 0.25
            reasons.append("special_privileges_human")
    elif event_id == 4776:
        reasons.append("credential_validation")
    elif event_id == 4688:
        if proc in SUSPICIOUS_PROCESSES and account_type == "human_user":
            risk += SUSPICIOUS_PROCESSES[proc]
            reasons.append(f"suspicious_process_{proc}")
        elif proc in SUSPICIOUS_PROCESSES:
            risk += SUSPICIOUS_PROCESSES[proc] * 0.35
            reasons.append(f"suspicious_process_nonhuman_{proc}")
        elif proc in NOISY_PROCESSES:
            risk = max(0.0, risk - 0.10)
            reasons.append(f"noisy_process_suppressed_{proc}")

        if proc == "cmd.exe" and parent and parent not in {"explorer.exe", "taskeng.exe", "services.exe", "cmd", "cmd.exe"}:
            risk += 0.15
            reasons.append(f"unusual_cmd_parent_{parent}")
        if proc == "powershell.exe" and parent and parent not in {"explorer.exe", "taskeng.exe", "powershell", "powershell.exe"}:
            risk += 0.20
            reasons.append(f"unusual_powershell_parent_{parent}")

    # Account suppression for routine low risk.
    if account_type == "system_account" and risk < 0.30:
        risk = max(0.03, risk * 0.50)
    elif account_type == "computer_account" and risk < 0.30:
        risk = max(0.03, risk * 0.70)
    elif account_type == "infrastructure_account" and risk < 0.40:
        risk = max(0.03, risk * 0.60)
    elif account_type == "service_account" and risk < 0.40:
        risk = max(0.03, risk * 0.70)

    evidence = host_evidence_from_reasons(reasons, account_type)
    host_key = host_key_from_host(event)
    matches = net_index.check(actor, host_key, ts, config.correlation_window_sec)

    max_quality = 0.0
    for scope, category, net_risk in matches:
        quality, q_reasons = correlation_quality(category, evidence, account_type)
        if quality > 0:
            reasons.append(f"correlation_{scope}_network_{category}_quality")
            reasons.extend(q_reasons)
        else:
            # Keep a weak trace only when there was already a suspicious host reason.
            if risk >= 0.2:
                reasons.append(f"correlation_{scope}_network_{category}_weak_trace")
                reasons.extend(q_reasons)
        max_quality = max(max_quality, quality)

    risk = min(1.0, risk + max_quality)
    return action_from_host_risk(risk), risk, reasons, account_type, max_quality


# ============================================================
# EPISODE COMPRESSION
# ============================================================

class EpisodeCompressor:
    def __init__(self, window_sec: int) -> None:
        self.window_sec = window_sec
        self.episodes: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def add(self, event: Dict[str, Any], risk: float, reasons: List[str], quality: float, account_type: str) -> None:
        host = host_key_from_host(event)
        bucket = event["timestamp"] // self.window_sec
        key = (host, bucket)

        ep = self.episodes.get(key)
        if not ep:
            ep = {
                "host": host,
                "bucket": bucket,
                "start_time": event["timestamp"],
                "end_time": event["timestamp"],
                "max_risk": risk,
                "max_quality": quality,
                "event_count": 0,
                "actors": Counter(),
                "processes": Counter(),
                "event_ids": Counter(),
                "account_types": Counter(),
                "reasons": Counter(),
                "recommended_action": "WATCH",
            }
            self.episodes[key] = ep

        ep["event_count"] += 1
        ep["start_time"] = min(ep["start_time"], event["timestamp"])
        ep["end_time"] = max(ep["end_time"], event["timestamp"])
        ep["max_risk"] = max(ep["max_risk"], risk)
        ep["max_quality"] = max(ep["max_quality"], quality)
        ep["actors"][event["actor"]] += 1
        if event.get("process_name"):
            ep["processes"][event.get("process_name")] += 1
        if event.get("event_id") is not None:
            ep["event_ids"][event.get("event_id")] += 1
        ep["account_types"][account_type] += 1
        for r in reasons:
            ep["reasons"][normalize_reason(r)] += 1

        if ep["max_risk"] >= 0.7 or ep["max_quality"] >= 0.35:
            ep["recommended_action"] = "HUMAN_REVIEW"
        elif ep["max_risk"] >= 0.4 or ep["max_quality"] >= 0.25:
            ep["recommended_action"] = "COLLECT_EVIDENCE"
        else:
            ep["recommended_action"] = "WATCH"

    def write(self, path: Path) -> int:
        count = 0
        with path.open("w", encoding="utf-8") as f:
            for ep in sorted(self.episodes.values(), key=lambda x: (x["start_time"], x["host"])):
                output = {
                    "host": ep["host"],
                    "start_time": ep["start_time"],
                    "end_time": ep["end_time"],
                    "duration": ep["end_time"] - ep["start_time"],
                    "event_count": ep["event_count"],
                    "max_risk": round(ep["max_risk"], 4),
                    "max_quality": round(ep["max_quality"], 4),
                    "recommended_action": ep["recommended_action"],
                    "top_actors": ep["actors"].most_common(10),
                    "top_processes": ep["processes"].most_common(10),
                    "top_event_ids": ep["event_ids"].most_common(10),
                    "account_types": ep["account_types"].most_common(10),
                    "top_reasons": ep["reasons"].most_common(15),
                }
                f.write(json.dumps(output) + "\n")
                count += 1
        return count


# ============================================================
# PROCESSOR
# ============================================================

@dataclass
class Stats:
    network: int = 0
    host: int = 0
    total: int = 0
    parse_failed: int = 0
    suspicious: int = 0
    correlations: int = 0
    high_signal_events: int = 0
    actions: Counter = field(default_factory=Counter)
    account_types: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)
    correlation_reasons: Counter = field(default_factory=Counter)
    actors: Counter = field(default_factory=Counter)
    resources: Counter = field(default_factory=Counter)


class SRIAProcessorV06:
    def __init__(self, config: ProcessorConfig) -> None:
        self.config = config
        self.dns = TimeWindowedDNS()
        self.net_index = SuspiciousNetworkIndex(config.max_network_events_per_key)
        self.episodes = EpisodeCompressor(config.episode_window_sec)
        self.stats = Stats()

        for p in [config.suspicious_file, config.correlation_file, config.episode_file, config.report_file]:
            p.parent.mkdir(parents=True, exist_ok=True)

    def _record(self, event: Dict[str, Any], action: str, risk: float, reasons: List[str]) -> None:
        self.stats.actions[action] += 1
        for r in reasons:
            nr = normalize_reason(r)
            self.stats.reasons[nr] += 1
            if nr.startswith("correlation_") or nr.startswith("quality_"):
                self.stats.correlation_reasons[nr] += 1
        if risk >= 0.2:
            self.stats.suspicious += 1
            self.stats.actors[event["actor"]] += 1
            self.stats.resources[event["resource"]] += 1

    @staticmethod
    def _write_jsonl(handle, event: Dict[str, Any], action: str, risk: float, reasons: List[str], extra: Dict[str, Any]) -> None:
        row = {
            "timestamp": event["timestamp"],
            "type": event["type"],
            "actor": event["actor"],
            "resource": event["resource"],
            "action": action,
            "risk": round(risk, 4),
            "reasons": reasons,
        }
        row.update(extra)
        handle.write(json.dumps(row) + "\n")

    def process_network(self, suspicious_handle) -> None:
        print("\nProcessing network events...")
        with self.config.network_file.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if self.config.max_events and self.stats.total >= self.config.max_events:
                    return
                event = parse_network_line(line)
                if not event:
                    self.stats.parse_failed += 1
                    continue

                self.stats.network += 1
                self.stats.total += 1
                action, risk, reasons, category = evaluate_network(event, self.config, self.dns)
                self._record(event, action, risk, reasons)

                if risk >= 0.2:
                    self._write_jsonl(
                        suspicious_handle,
                        event,
                        action,
                        risk,
                        reasons,
                        {
                            "dst_port": event["dst_port"],
                            "src_bytes": event["src_bytes"],
                            "dst_bytes": event["dst_bytes"],
                            "category": category,
                        },
                    )
                    if category in {"large_outbound", "dns_flood", "suspicious_port"}:
                        self.net_index.add(event["actor"], host_key_from_network(event), event["timestamp"], risk, category)

                if self.stats.total % self.config.progress_every == 0:
                    self.print_progress()

    def process_host(self, suspicious_handle, correlation_handle) -> None:
        print("\nProcessing host events...")
        with self.config.host_file.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if self.config.max_events and self.stats.total >= self.config.max_events:
                    return
                event = parse_host_line(line)
                if not event:
                    self.stats.parse_failed += 1
                    continue

                self.stats.host += 1
                self.stats.total += 1

                action, risk, reasons, account_type, quality = evaluate_host(event, self.config, self.net_index)
                self.stats.account_types[account_type] += 1
                self._record(event, action, risk, reasons)

                extra = {
                    "event_id": event.get("event_id"),
                    "process": event.get("process_name", ""),
                    "parent_process": event.get("parent_process_name", ""),
                    "account_type": account_type,
                    "correlation_quality": round(quality, 4),
                    "source": event.get("source"),
                    "destination": event.get("destination"),
                }

                if risk >= 0.2:
                    self._write_jsonl(suspicious_handle, event, action, risk, reasons, extra)

                has_correlation = any(r.startswith("correlation_") for r in reasons)
                has_quality = quality > 0
                if has_correlation and has_quality:
                    self.stats.correlations += 1
                    self._write_jsonl(correlation_handle, event, action, risk, reasons, extra)

                if quality >= self.config.episode_min_quality:
                    self.stats.high_signal_events += 1
                    self.episodes.add(event, risk, reasons, quality, account_type)

                if self.stats.total % self.config.progress_every == 0:
                    self.print_progress()

    def print_progress(self) -> None:
        print(
            f"  Processed {self.stats.total:,} events... "
            f"(suspicious: {self.stats.suspicious:,}, quality_correlations: {self.stats.correlations:,}, "
            f"episodes_events: {self.stats.high_signal_events:,}, network_indexed: {self.net_index.total_indexed:,})"
        )

    def run(self) -> None:
        print("=" * 72)
        print("SRIA LANL Processor v0.6")
        print("  - Correlation Quality Gate")
        print("  - Large-outbound-only correlation downgraded")
        print("  - Episode compression")
        print("=" * 72)
        print(f"Network: {self.config.network_file}")
        print(f"Host: {self.config.host_file}")
        print(f"Suspicious output: {self.config.suspicious_file}")
        print(f"Correlation output: {self.config.correlation_file}")
        print(f"Episode output: {self.config.episode_file}")
        print(f"Max events: {'unlimited' if self.config.max_events == 0 else self.config.max_events}")
        print("=" * 72)

        with self.config.suspicious_file.open("w", encoding="utf-8") as suspicious_handle, \
             self.config.correlation_file.open("w", encoding="utf-8") as correlation_handle:
            self.process_network(suspicious_handle)
            self.process_host(suspicious_handle, correlation_handle)

        episode_count = self.episodes.write(self.config.episode_file)
        self.print_report(episode_count)
        self.write_report(episode_count)

    def print_report(self, episode_count: int) -> None:
        total = max(1, self.stats.total)
        print("\n" + "=" * 72)
        print("PROCESSING STATISTICS")
        print("=" * 72)
        print(f"Network events: {self.stats.network:,}")
        print(f"Host events: {self.stats.host:,}")
        print(f"Total events: {self.stats.total:,}")
        print(f"Parse failures: {self.stats.parse_failed:,}")
        print(f"Suspicious events: {self.stats.suspicious:,}")
        print(f"Quality-gated correlated events: {self.stats.correlations:,}")
        print(f"High-signal episode events: {self.stats.high_signal_events:,}")
        print(f"Compressed episodes: {episode_count:,}")
        print(f"Suspicious network indexed: {self.net_index.total_indexed:,}")
        print(f"Network index cap drops: {self.net_index.cap_drops:,}")
        print(f"Suspicious rate: {self.stats.suspicious / total * 100:.2f}%")
        print(f"Quality-correlation rate: {self.stats.correlations / total * 100:.4f}%")

        def show(title, counter, n=10):
            print(f"\n{title}:")
            for k, v in counter.most_common(n):
                print(f"  {k}: {v:,}")

        show("Actions", self.stats.actions)
        show("Account types", self.stats.account_types)
        show("Top normalized reasons", self.stats.reasons)
        show("Top correlation/quality reasons", self.stats.correlation_reasons)
        show("Top suspicious actors", self.stats.actors)
        show("Top suspicious resources", self.stats.resources)
        print(f"\nSuspicious events saved to: {self.config.suspicious_file}")
        print(f"Quality correlations saved to: {self.config.correlation_file}")
        print(f"High-signal episodes saved to: {self.config.episode_file}")
        print(f"Report saved to: {self.config.report_file}")
        print("=" * 72)

    def write_report(self, episode_count: int) -> None:
        total = max(1, self.stats.total)
        with self.config.report_file.open("w", encoding="utf-8") as f:
            f.write("SRIA LANL Processor v0.6 Report\n")
            f.write("=" * 72 + "\n\n")
            f.write(f"Network events: {self.stats.network:,}\n")
            f.write(f"Host events: {self.stats.host:,}\n")
            f.write(f"Total events: {self.stats.total:,}\n")
            f.write(f"Parse failures: {self.stats.parse_failed:,}\n")
            f.write(f"Suspicious events: {self.stats.suspicious:,}\n")
            f.write(f"Quality-gated correlated events: {self.stats.correlations:,}\n")
            f.write(f"High-signal episode events: {self.stats.high_signal_events:,}\n")
            f.write(f"Compressed episodes: {episode_count:,}\n")
            f.write(f"Suspicious network indexed: {self.net_index.total_indexed:,}\n")
            f.write(f"Network index cap drops: {self.net_index.cap_drops:,}\n")
            f.write(f"Suspicious rate: {self.stats.suspicious / total * 100:.2f}%\n")
            f.write(f"Quality-correlation rate: {self.stats.correlations / total * 100:.4f}%\n\n")

            for title, counter in [
                ("Actions", self.stats.actions),
                ("Account types", self.stats.account_types),
                ("Top normalized reasons", self.stats.reasons),
                ("Top correlation/quality reasons", self.stats.correlation_reasons),
                ("Top suspicious actors", self.stats.actors),
                ("Top suspicious resources", self.stats.resources),
            ]:
                f.write(title + ":\n")
                for k, v in counter.most_common(25):
                    f.write(f"  {k}: {v:,}\n")
                f.write("\n")


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> None:
    network_lines = [
        "100,0,CompHost1,CompExternal,6,Port12345,80,10,0,200000,0",
        "110,0,CompHost2,CompBad,6,Port11111,4444,5,0,500,0",
        "120,0,CompDns,CompResolver,17,Port10000,53,1,0,70,0",
        "121,0,CompDns,CompResolver,17,Port10001,53,1,0,70,0",
        "122,0,CompDns,CompResolver,17,Port10002,53,1,0,70,0",
        "123,0,CompDns,CompResolver,17,Port10003,53,1,0,70,0",
        "124,0,CompDns,CompResolver,17,Port10004,53,1,0,70,0",
        "125,0,CompDns,CompResolver,17,Port10005,53,1,0,70,0",
    ]
    host_lines = [
        '{"UserName":"UserA","EventID":4688,"LogHost":"CompHost1","ProcessName":"cmd.exe","ParentProcessName":"ProcX.exe","Time":150}',
        '{"UserName":"CompHost2$","EventID":4688,"LogHost":"CompHost2","ProcessName":"cscript.exe","ParentProcessName":"Proc950869","Time":130}',
        '{"UserName":"system","EventID":4672,"LogHost":"CompSystem","Time":130}',
        '{"UserName":"UserB","EventID":4648,"LogHost":"CompDns","Destination":"CompX","Time":126}',
    ]

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        net = root / "net.csv"
        host = root / "host.json"
        sus = root / "sus.jsonl"
        corr = root / "corr.jsonl"
        ep = root / "ep.jsonl"
        rep = root / "report.txt"
        net.write_text("\n".join(network_lines) + "\n", encoding="utf-8")
        host.write_text("\n".join(host_lines) + "\n", encoding="utf-8")

        cfg = ProcessorConfig(
            network_file=net,
            host_file=host,
            suspicious_file=sus,
            correlation_file=corr,
            episode_file=ep,
            report_file=rep,
            normal_dns_threshold=5,
            normal_large_transfer_bytes=100_000,
            progress_every=1000,
        )
        p = SRIAProcessorV06(cfg)
        p.run()

        assert sus.exists() and sus.read_text(encoding="utf-8").strip(), "missing suspicious output"
        assert corr.exists() and corr.read_text(encoding="utf-8").strip(), "missing quality correlation output"
        assert ep.exists() and ep.read_text(encoding="utf-8").strip(), "missing episode output"
        assert rep.exists(), "missing report"
        print("\nSelf-test PASSED.")


# ============================================================
# CLI
# ============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SRIA LANL Processor v0.6")
    parser.add_argument("--network", type=Path, default=Path(DEFAULT_NETWORK_FILE))
    parser.add_argument("--host", type=Path, default=Path(DEFAULT_HOST_FILE))
    parser.add_argument("--suspicious-output", type=Path, default=Path(DEFAULT_SUSPICIOUS_FILE))
    parser.add_argument("--correlation-output", type=Path, default=Path(DEFAULT_CORRELATION_FILE))
    parser.add_argument("--episode-output", type=Path, default=Path(DEFAULT_EPISODE_FILE))
    parser.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_FILE))
    parser.add_argument("--max-events", type=int, default=0)
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    parser.add_argument("--max-per-key", type=int, default=5000)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    if args.self_test:
        run_self_test()
        return

    cfg = ProcessorConfig(
        network_file=args.network,
        host_file=args.host,
        suspicious_file=args.suspicious_output,
        correlation_file=args.correlation_output,
        episode_file=args.episode_output,
        report_file=args.report,
        max_events=args.max_events,
        progress_every=args.progress_every,
        max_network_events_per_key=args.max_per_key,
    )
    SRIAProcessorV06(cfg).run()


if __name__ == "__main__":
    main()
