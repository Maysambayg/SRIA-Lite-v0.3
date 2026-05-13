#!/usr/bin/env python3
"""
SRIA LANL Processor v0.5.2

Optimized host/network correlation-prep processor.

Fixes from v0.5.1:
- Does NOT store every network event for correlation.
- Stores only suspicious network events in compact indexes.
- Uses timestamp-sorted indexes plus binary search for fast correlation lookup.
- Streams suspicious JSONL output immediately.
- Streams correlation JSONL output immediately.
- Adds bounded per-key storage caps.
- Adds internal self-test.
- Keeps batch processing explicit: network first, host second.
  This is not full chronological reconstruction; it is fast correlation-prep.

Run:
    py sria_v05_2.py
    py sria_v05_2.py --max-events 100000
    py sria_v05_2.py --self-test
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


DEFAULT_NETWORK_FILE = r"F:\SRIA\netflow_day-90.csv"
DEFAULT_HOST_FILE = r"F:\SRIA\wls_day-90.json"
DEFAULT_OUTPUT_FILE = r"F:\SRIA\suspicious_events_v05_2.jsonl"
DEFAULT_CORRELATION_FILE = r"F:\SRIA\correlation_events_v05_2.jsonl"
DEFAULT_REPORT_FILE = r"F:\SRIA\sria_v05_2_report.txt"


@dataclass
class ProcessorConfig:
    network_file: Path = Path(DEFAULT_NETWORK_FILE)
    host_file: Path = Path(DEFAULT_HOST_FILE)
    output_file: Path = Path(DEFAULT_OUTPUT_FILE)
    correlation_file: Path = Path(DEFAULT_CORRELATION_FILE)
    report_file: Path = Path(DEFAULT_REPORT_FILE)
    max_events: int = 0
    progress_every: int = 1_000_000
    normal_dns_threshold: int = 100
    normal_dns_window_sec: int = 60
    normal_large_transfer_bytes: int = 100_000
    normal_watch_ports: set[int] = field(default_factory=lambda: {4444, 5555, 6666, 7777, 8888, 9999})
    infra_dns_threshold: int = 500
    infra_dns_window_sec: int = 60
    infra_large_transfer_bytes: int = 1_000_000
    infra_watch_ports: set[int] = field(default_factory=set)
    correlation_window_sec: int = 300
    max_suspicious_network_per_key: int = 5000


INFRASTRUCTURE_RESOURCES = {
    "Comp275646",
    "Comp387111",
    "ActiveDirectory",
    "Mail",
    "VPN",
    "EnterpriseAppServer",
    "DNS",
    "Gateway",
    "Proxy",
}

INFRASTRUCTURE_ACTORS = {
    "VPN",
    "system",
    "SYSTEM",
    "NETWORK SERVICE",
    "LOCAL SERVICE",
    "ActiveDirectory$",
    "EnterpriseAppServer$",
}

SERVICE_ACCOUNT_PREFIXES = ("svc", "appservice", "service")

HOST_BASE_RISKS = {
    4624: 0.05,
    4625: 0.60,
    4634: 0.00,
    4648: 0.35,
    4672: 0.15,
    4688: 0.10,
    4768: 0.05,
    4769: 0.05,
    4776: 0.30,
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
    "taskeng.exe",
    "conhost.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "spoolsv.exe",
}


def classify_actor(actor: str) -> str:
    if not actor:
        return "unknown"
    actor_lower = actor.lower()
    if actor_lower in {"system", "nt authority\\system", "local service", "network service"}:
        return "system_account"
    if actor in INFRASTRUCTURE_ACTORS:
        return "infrastructure_account"
    if any(actor_lower.startswith(prefix) for prefix in SERVICE_ACCOUNT_PREFIXES):
        return "service_account"
    if actor.endswith("$"):
        return "computer_account"
    if actor_lower.startswith("user"):
        return "human_user"
    return "human_user"


def is_infrastructure(actor: Optional[str] = None, resource: Optional[str] = None) -> bool:
    if actor and actor in INFRASTRUCTURE_ACTORS:
        return True
    if resource and resource in INFRASTRUCTURE_RESOURCES:
        return True
    return False


def host_key_from_network(event: Dict[str, Any]) -> str:
    return str(event.get("actor") or "unknown")


def host_key_from_host(event: Dict[str, Any]) -> str:
    return str(event.get("resource") or "unknown")


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
    """Index only suspicious network events for fast host-phase correlation."""

    def __init__(self, max_per_key: int = 5000) -> None:
        self.max_per_key = max_per_key
        self.by_actor: Dict[str, List[Tuple[int, float, str]]] = defaultdict(list)
        self.by_host: Dict[str, List[Tuple[int, float, str]]] = defaultdict(list)
        self.total_indexed = 0
        self.dropped_due_to_cap = 0

    def add(self, actor: str, host_key: str, timestamp: int, risk: float, category: str) -> None:
        self._append_capped(self.by_actor[actor], (timestamp, risk, category))
        self._append_capped(self.by_host[host_key], (timestamp, risk, category))
        self.total_indexed += 1

    def _append_capped(self, items: List[Tuple[int, float, str]], item: Tuple[int, float, str]) -> None:
        items.append(item)
        if len(items) > self.max_per_key:
            del items[: len(items) - self.max_per_key]
            self.dropped_due_to_cap += 1

    @staticmethod
    def _find_window(items: List[Tuple[int, float, str]], timestamp: int, window_sec: int) -> Optional[Tuple[int, float, str]]:
        if not items:
            return None
        lo_ts = timestamp - window_sec
        hi_ts = timestamp + window_sec
        left = bisect.bisect_left(items, (lo_ts, -1.0, ""))
        right = bisect.bisect_right(items, (hi_ts, 2.0, "zzzz"))
        if left >= right:
            return None
        best = None
        for item in items[left:right]:
            if best is None or item[1] > best[1]:
                best = item
        return best

    def check(self, actor: str, host_key: str, timestamp: int, window_sec: int) -> Tuple[List[str], float]:
        reasons: List[str] = []
        boost = 0.0
        actor_match = self._find_window(self.by_actor.get(actor, []), timestamp, window_sec)
        if actor_match:
            _ts, _risk, category = actor_match
            reasons.append(f"correlation_actor_network_{category}_within_window")
            boost += 0.15
        host_match = self._find_window(self.by_host.get(host_key, []), timestamp, window_sec)
        if host_match:
            _ts, _risk, category = host_match
            reasons.append(f"correlation_hostkey_network_{category}_within_window")
            boost += 0.20
        return reasons, min(boost, 0.35)


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
            "duration": int(parts[1]) if str(parts[1]).isdigit() else 0,
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
    if reason.startswith("correlation_"):
        return reason
    if reason.startswith("noisy_process_suppressed"):
        return "noisy_process_suppressed"
    if reason.startswith("unusual_"):
        return "unusual_parent_process"
    if reason == "infrastructure_downgrade":
        return "infrastructure_downgrade"
    return reason or "none"


def reason_category_from_reasons(reasons: List[str]) -> str:
    normalized = [normalize_reason(r) for r in reasons]
    for wanted in (
        "dns_flood",
        "large_outbound",
        "suspicious_port",
        "suspicious_process",
        "explicit_credential",
        "special_privileges",
        "failed_logon",
        "credential_validation",
    ):
        if wanted in normalized:
            return wanted
    return "other"


def evaluate_network(
    event: Dict[str, Any],
    config: ProcessorConfig,
    dns_tracker: TimeWindowedDNS,
) -> Tuple[str, float, List[str], str]:
    actor = event["actor"]
    resource = event["resource"]
    dst_port = event["dst_port"]
    src_bytes = event["src_bytes"]
    timestamp = event["timestamp"]
    infra = is_infrastructure(actor=actor, resource=resource)

    if infra:
        dns_threshold = config.infra_dns_threshold
        dns_window = config.infra_dns_window_sec
        large_threshold = config.infra_large_transfer_bytes
        watch_ports = config.infra_watch_ports
    else:
        dns_threshold = config.normal_dns_threshold
        dns_window = config.normal_dns_window_sec
        large_threshold = config.normal_large_transfer_bytes
        watch_ports = config.normal_watch_ports

    risk = 0.0
    reasons: List[str] = []

    if dst_port in watch_ports:
        risk += 0.60
        reasons.append(f"suspicious_port_{dst_port}")

    if src_bytes > large_threshold:
        risk += 0.30
        reasons.append(f"large_outbound_{src_bytes}")

    if dst_port == 53:
        dns_count = dns_tracker.add_query(timestamp, actor, resource, window_sec=dns_window)
        if dns_count >= dns_threshold:
            risk += 0.50
            reasons.append(f"dns_flood_{dns_count}_in_{dns_window}s")

    if infra and risk >= 0.7:
        has_dns = any("dns_flood" in r for r in reasons)
        has_large = any("large_outbound" in r for r in reasons)
        has_port = any("suspicious_port" in r for r in reasons)
        if has_dns and has_large and not has_port:
            risk = 0.55
            reasons.append("infrastructure_downgrade")

    category = reason_category_from_reasons(reasons)
    action = action_from_network_risk(min(risk, 1.0))
    return action, min(risk, 1.0), reasons, category


def evaluate_host(
    event: Dict[str, Any],
    config: ProcessorConfig,
    net_index: SuspiciousNetworkIndex,
) -> Tuple[str, float, List[str], str]:
    actor = event["actor"]
    timestamp = event["timestamp"]
    event_id = event.get("event_id")
    process_name = (event.get("process_name") or "").lower()
    parent_process = (event.get("parent_process_name") or "").lower()
    account_type = classify_actor(actor)
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
        if process_name in SUSPICIOUS_PROCESSES and account_type == "human_user":
            risk += SUSPICIOUS_PROCESSES[process_name]
            reasons.append(f"suspicious_process_{process_name}")
        elif process_name in SUSPICIOUS_PROCESSES and account_type != "human_user":
            risk += SUSPICIOUS_PROCESSES[process_name] * 0.35
            reasons.append(f"suspicious_process_nonhuman_{process_name}")
        elif process_name in NOISY_PROCESSES:
            risk = max(0.0, risk - 0.10)
            reasons.append(f"noisy_process_suppressed_{process_name}")

        if process_name == "cmd.exe" and parent_process and parent_process not in {
            "explorer.exe",
            "taskeng.exe",
            "services.exe",
            "cmd",
            "cmd.exe",
        }:
            risk += 0.15
            reasons.append(f"unusual_cmd_parent_{parent_process}")

        if process_name == "powershell.exe" and parent_process and parent_process not in {
            "explorer.exe",
            "taskeng.exe",
            "powershell",
            "powershell.exe",
        }:
            risk += 0.20
            reasons.append(f"unusual_powershell_parent_{parent_process}")

    if account_type == "system_account" and risk < 0.30:
        risk = max(0.03, risk * 0.50)
    elif account_type == "computer_account" and risk < 0.30:
        risk = max(0.03, risk * 0.70)
    elif account_type == "infrastructure_account" and risk < 0.40:
        risk = max(0.03, risk * 0.60)
    elif account_type == "service_account" and risk < 0.40:
        risk = max(0.03, risk * 0.70)

    host_key = host_key_from_host(event)
    corr_reasons, boost = net_index.check(actor, host_key, timestamp, config.correlation_window_sec)
    if corr_reasons:
        reasons.extend(corr_reasons)
        risk = min(1.0, risk + boost)

    action = action_from_host_risk(min(risk, 1.0))
    return action, min(risk, 1.0), reasons, account_type


@dataclass
class ProcessingStats:
    network: int = 0
    host: int = 0
    total: int = 0
    suspicious: int = 0
    correlations: int = 0
    parse_failed: int = 0
    actions: Counter = field(default_factory=Counter)
    account_types: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)
    correlation_reasons: Counter = field(default_factory=Counter)
    actors: Counter = field(default_factory=Counter)
    resources: Counter = field(default_factory=Counter)


class SRIAProcessorV052:
    def __init__(self, config: ProcessorConfig) -> None:
        self.config = config
        self.dns_tracker = TimeWindowedDNS()
        self.net_index = SuspiciousNetworkIndex(max_per_key=config.max_suspicious_network_per_key)
        self.stats = ProcessingStats()
        self.config.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.correlation_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.report_file.parent.mkdir(parents=True, exist_ok=True)

    def _record(self, event: Dict[str, Any], action: str, risk: float, reasons: List[str]) -> None:
        self.stats.actions[action] += 1
        for reason in reasons:
            self.stats.reasons[normalize_reason(reason)] += 1
        if risk >= 0.2:
            self.stats.suspicious += 1
            self.stats.actors[event["actor"]] += 1
            self.stats.resources[event["resource"]] += 1

    def _write_jsonl(self, handle, event: Dict[str, Any], action: str, risk: float, reasons: List[str], extra: Optional[Dict[str, Any]] = None) -> None:
        output = {
            "timestamp": event["timestamp"],
            "type": event["type"],
            "actor": event["actor"],
            "resource": event["resource"],
            "action": action,
            "risk": round(float(risk), 4),
            "reasons": reasons,
        }
        if extra:
            output.update(extra)
        handle.write(json.dumps(output) + "\n")

    def process_network(self, suspicious_handle) -> None:
        if not self.config.network_file.exists():
            print(f"Network file not found: {self.config.network_file}")
            return
        print("\nProcessing network events...")
        with open(self.config.network_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if self.config.max_events > 0 and self.stats.total >= self.config.max_events:
                    return
                event = parse_network_line(line)
                if not event:
                    self.stats.parse_failed += 1
                    continue
                self.stats.network += 1
                self.stats.total += 1
                action, risk, reasons, category = evaluate_network(event, self.config, self.dns_tracker)
                self._record(event, action, risk, reasons)
                if risk >= 0.2:
                    self._write_jsonl(
                        suspicious_handle,
                        event,
                        action,
                        risk,
                        reasons,
                        extra={
                            "dst_port": event["dst_port"],
                            "src_bytes": event["src_bytes"],
                            "dst_bytes": event["dst_bytes"],
                            "category": category,
                        },
                    )
                    self.net_index.add(
                        actor=event["actor"],
                        host_key=host_key_from_network(event),
                        timestamp=event["timestamp"],
                        risk=risk,
                        category=category,
                    )
                if self.stats.total % self.config.progress_every == 0:
                    self.print_progress()

    def process_host(self, suspicious_handle, correlation_handle) -> None:
        if not self.config.host_file.exists():
            print(f"Host file not found: {self.config.host_file}")
            return
        print("\nProcessing host events...")
        with open(self.config.host_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if self.config.max_events > 0 and self.stats.total >= self.config.max_events:
                    return
                event = parse_host_line(line)
                if not event:
                    self.stats.parse_failed += 1
                    continue
                self.stats.host += 1
                self.stats.total += 1
                action, risk, reasons, account_type = evaluate_host(event, self.config, self.net_index)
                self.stats.account_types[account_type] += 1
                self._record(event, action, risk, reasons)
                if risk >= 0.2:
                    extra = {
                        "event_id": event.get("event_id"),
                        "process": event.get("process_name", ""),
                        "parent_process": event.get("parent_process_name", ""),
                        "account_type": account_type,
                        "source": event.get("source"),
                        "destination": event.get("destination"),
                    }
                    self._write_jsonl(suspicious_handle, event, action, risk, reasons, extra=extra)
                    corr_reasons = [r for r in reasons if r.startswith("correlation_")]
                    if corr_reasons:
                        self.stats.correlations += 1
                        for reason in corr_reasons:
                            self.stats.correlation_reasons[reason] += 1
                        self._write_jsonl(correlation_handle, event, action, risk, reasons, extra=extra)
                if self.stats.total % self.config.progress_every == 0:
                    self.print_progress()

    def print_progress(self) -> None:
        print(
            f"  Processed {self.stats.total:,} events... "
            f"(suspicious: {self.stats.suspicious:,}, correlations: {self.stats.correlations:,}, "
            f"network_indexed: {self.net_index.total_indexed:,})"
        )

    def run(self) -> None:
        print("=" * 72)
        print("SRIA LANL Processor v0.5.2")
        print("  - Optimized suspicious-network-only correlation index")
        print("  - Host rule calibration")
        print("  - Streaming JSONL output")
        print("  - Actor + host-key correlation")
        print("=" * 72)
        print(f"Network: {self.config.network_file}")
        print(f"Host: {self.config.host_file}")
        print(f"Output: {self.config.output_file}")
        print(f"Correlation output: {self.config.correlation_file}")
        print(f"Max events: {'unlimited' if self.config.max_events == 0 else self.config.max_events}")
        print("=" * 72)
        with open(self.config.output_file, "w", encoding="utf-8") as suspicious_handle, open(self.config.correlation_file, "w", encoding="utf-8") as correlation_handle:
            self.process_network(suspicious_handle)
            self.process_host(suspicious_handle, correlation_handle)
        self.print_final_report()
        self.write_report()

    def print_final_report(self) -> None:
        total = max(1, self.stats.total)
        print("\n" + "=" * 72)
        print("PROCESSING STATISTICS")
        print("=" * 72)
        print(f"Network events: {self.stats.network:,}")
        print(f"Host events: {self.stats.host:,}")
        print(f"Total events: {self.stats.total:,}")
        print(f"Parse failures: {self.stats.parse_failed:,}")
        print(f"Suspicious events (risk >= 0.2): {self.stats.suspicious:,}")
        print(f"Correlated events (host+network): {self.stats.correlations:,}")
        print(f"Suspicious network events indexed: {self.net_index.total_indexed:,}")
        print(f"Network index cap drops: {self.net_index.dropped_due_to_cap:,}")
        print(f"Percentage suspicious: {self.stats.suspicious / total * 100:.2f}%")
        print(f"Percentage correlated: {self.stats.correlations / total * 100:.4f}%")
        print("\nActions taken:")
        for action, count in self.stats.actions.most_common():
            print(f"  {action}: {count:,}")
        print("\nAccount types:")
        for account_type, count in self.stats.account_types.most_common():
            print(f"  {account_type}: {count:,}")
        print("\nTop 10 normalized reasons:")
        for reason, count in self.stats.reasons.most_common(10):
            print(f"  {reason}: {count:,}")
        print("\nTop 10 correlation reasons:")
        for reason, count in self.stats.correlation_reasons.most_common(10):
            print(f"  {reason}: {count:,}")
        print("\nTop 10 suspicious actors:")
        for actor, count in self.stats.actors.most_common(10):
            print(f"  {actor}: {count:,}")
        print("\nTop 10 suspicious resources:")
        for resource, count in self.stats.resources.most_common(10):
            print(f"  {resource}: {count:,}")
        print(f"\nSuspicious events saved to: {self.config.output_file}")
        print(f"Correlated events saved to: {self.config.correlation_file}")
        print(f"Report saved to: {self.config.report_file}")
        print("=" * 72)

    def write_report(self) -> None:
        total = max(1, self.stats.total)
        with open(self.config.report_file, "w", encoding="utf-8") as f:
            f.write("SRIA LANL Processor v0.5.2 Report\n")
            f.write("=" * 72 + "\n\n")
            f.write(f"Network events: {self.stats.network:,}\n")
            f.write(f"Host events: {self.stats.host:,}\n")
            f.write(f"Total events: {self.stats.total:,}\n")
            f.write(f"Parse failures: {self.stats.parse_failed:,}\n")
            f.write(f"Suspicious events: {self.stats.suspicious:,}\n")
            f.write(f"Correlated events: {self.stats.correlations:,}\n")
            f.write(f"Suspicious network events indexed: {self.net_index.total_indexed:,}\n")
            f.write(f"Network index cap drops: {self.net_index.dropped_due_to_cap:,}\n")
            f.write(f"Percentage suspicious: {self.stats.suspicious / total * 100:.2f}%\n")
            f.write(f"Percentage correlated: {self.stats.correlations / total * 100:.4f}%\n\n")
            f.write("Actions taken:\n")
            for action, count in self.stats.actions.most_common():
                f.write(f"  {action}: {count:,}\n")
            f.write("\nAccount types:\n")
            for account_type, count in self.stats.account_types.most_common():
                f.write(f"  {account_type}: {count:,}\n")
            f.write("\nTop normalized reasons:\n")
            for reason, count in self.stats.reasons.most_common(25):
                f.write(f"  {reason}: {count:,}\n")
            f.write("\nTop correlation reasons:\n")
            for reason, count in self.stats.correlation_reasons.most_common(25):
                f.write(f"  {reason}: {count:,}\n")
            f.write("\nTop suspicious actors:\n")
            for actor, count in self.stats.actors.most_common(25):
                f.write(f"  {actor}: {count:,}\n")
            f.write("\nTop suspicious resources:\n")
            for resource, count in self.stats.resources.most_common(25):
                f.write(f"  {resource}: {count:,}\n")


def run_self_test() -> None:
    network_lines = [
        "100,0,CompA,CompB,6,Port12345,4444,100,0,50000,0",
        "150,0,CompHost1,CompExternal,6,Port12345,80,10,0,200000,0",
        "200,0,CompDns,CompResolver,17,Port10000,53,1,0,70,0",
        "201,0,CompDns,CompResolver,17,Port10001,53,1,0,70,0",
        "202,0,CompDns,CompResolver,17,Port10002,53,1,0,70,0",
        "203,0,CompDns,CompResolver,17,Port10003,53,1,0,70,0",
        "204,0,CompDns,CompResolver,17,Port10004,53,1,0,70,0",
        "205,0,CompDns,CompResolver,17,Port10005,53,1,0,70,0",
    ]
    host_lines = [
        '{"UserName":"UserA","EventID":4688,"LogHost":"CompHost1","ProcessName":"cmd.exe","ParentProcessName":"ProcX.exe","Time":160}',
        '{"UserName":"system","EventID":4672,"LogHost":"CompHost2","Time":130}',
        '{"UserName":"UserB","EventID":4648,"LogHost":"CompHost3","Destination":"CompX","Time":140}',
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        network_file = tmp / "network.csv"
        host_file = tmp / "host.json"
        output_file = tmp / "suspicious.jsonl"
        correlation_file = tmp / "correlation.jsonl"
        report_file = tmp / "report.txt"
        network_file.write_text("\n".join(network_lines) + "\n", encoding="utf-8")
        host_file.write_text("\n".join(host_lines) + "\n", encoding="utf-8")
        config = ProcessorConfig(
            network_file=network_file,
            host_file=host_file,
            output_file=output_file,
            correlation_file=correlation_file,
            report_file=report_file,
            max_events=0,
            progress_every=1000,
            normal_dns_threshold=5,
            normal_large_transfer_bytes=100_000,
            max_suspicious_network_per_key=100,
        )
        processor = SRIAProcessorV052(config)
        processor.run()
        assert output_file.exists(), "suspicious output was not created"
        assert correlation_file.exists(), "correlation output was not created"
        assert report_file.exists(), "report was not created"
        suspicious_lines = [line for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert suspicious_lines, "expected suspicious events"
        correlation_lines = [line for line in correlation_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert correlation_lines, "expected correlated events"
        print("\nSelf-test PASSED.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SRIA LANL Processor v0.5.2")
    parser.add_argument("--network", type=Path, default=Path(DEFAULT_NETWORK_FILE), help="LANL network CSV file")
    parser.add_argument("--host", type=Path, default=Path(DEFAULT_HOST_FILE), help="LANL host JSONL file")
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT_FILE), help="Suspicious events JSONL output")
    parser.add_argument("--correlation-output", type=Path, default=Path(DEFAULT_CORRELATION_FILE), help="Correlated events JSONL output")
    parser.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_FILE), help="Text report output")
    parser.add_argument("--max-events", type=int, default=0, help="Max events to process; 0 means unlimited")
    parser.add_argument("--progress-every", type=int, default=1_000_000, help="Progress print interval")
    parser.add_argument("--max-per-key", type=int, default=5000, help="Max suspicious network events stored per actor/host key")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return
    config = ProcessorConfig(
        network_file=args.network,
        host_file=args.host,
        output_file=args.output,
        correlation_file=args.correlation_output,
        report_file=args.report,
        max_events=args.max_events,
        progress_every=args.progress_every,
        max_suspicious_network_per_key=args.max_per_key,
    )
    processor = SRIAProcessorV052(config)
    processor.run()


if __name__ == "__main__":
    main()
