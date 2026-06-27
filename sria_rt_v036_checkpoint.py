#!/usr/bin/env python3
"""
sria_rt_v036_checkpoint.py

SRIA RT v0.3.6 - Stateful Batch Runner for v0.3.5 Scoring

Purpose:
- Keep the v0.3.5 scoring/gating logic unchanged.
- Run huge auth.txt jobs safely in smaller sequential batches.
- Preserve detector memory across batches so first-time edges remain valid.
- Stream finalized accepted/suppressed episodes to JSONL instead of holding
  everything in RAM.
- Save checkpoint/resume state: file byte offset, sparse-window pointer,
  detector memory, active episodes, counters, summaries, and validation sets.

IMPORTANT:
- This script imports sria_rt_v035.py from the same directory.
- redteam.txt is used only for sparse-window selection and post-hoc validation.
- Detector scoring uses auth.txt only.

Typical use:
    py sria_rt_v036_checkpoint.py --base-dir . --out-dir v036_batches --max-candidate-events 5000000 --force-start
    py sria_rt_v036_checkpoint.py --base-dir . --out-dir v036_batches --resume --max-candidate-events 5000000
    py sria_rt_v036_checkpoint.py --base-dir . --out-dir v036_batches --resume --finish
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import pickle
import sys
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from sria_rt_v035 import (
        Config,
        PrecisionDetectorV035,
        parse_auth_line,
        load_redteam,
        merge_windows,
        in_windows,
        episode_to_dict,
        summarize_episodes,
        find_suppressed_near_matches,
    )
except Exception as exc:  # pragma: no cover
    print("ERROR: sria_rt_v036_checkpoint.py requires sria_rt_v035.py in the same directory.")
    print(f"Import failure: {exc}")
    sys.exit(2)

VERSION = "v036"


def _counter_to_dict(c: Counter) -> Dict[str, int]:
    return {str(k): int(v) for k, v in c.items()}


def _dict_to_counter(d: Dict[str, int]) -> Counter:
    c = Counter()
    for k, v in (d or {}).items():
        c[k] = int(v)
    return c


class StreamingRunState:
    """Mutable state that is checkpointed between invocations."""

    def __init__(self, config: Config, windows: List[Tuple[int, int]], redteam: List[dict]) -> None:
        self.config = config
        self.windows = windows
        self.redteam = redteam

        self.detector = PrecisionDetectorV035(config)

        # File progress.
        self.byte_offset = 0
        self.scanned_lines = 0
        self.candidate_events = 0
        self.pointer = 0
        self.observed_min_ts: Optional[int] = None
        self.observed_max_ts: Optional[int] = None

        # Invocation/batch progress.
        self.batch_index = 0
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.finished = False

        # Output/validation totals.
        self.accepted_count = 0
        self.suppressed_count = 0
        self.near_match_written = 0

        self.accepted_signal_counts: Counter = Counter()
        self.accepted_gate_counts: Counter = Counter()
        self.suppressed_signal_counts: Counter = Counter()
        self.suppressed_gate_counts: Counter = Counter()
        self.suppressed_reason_counts: Counter = Counter()
        self.suppressed_entropy_counts: Counter = Counter()

        self.matched_redteam: Set[Tuple[int, str, str, str]] = set()
        self.exact_start_redteam: Set[Tuple[int, str, str, str]] = set()
        self.matched_episode_ids: Set[int] = set()
        self.match_gate_counts: Counter = Counter()
        self.exact_start_gate_counts: Counter = Counter()
        self.matched_episode_gate_by_id: Dict[int, str] = {}

        # Top ranked accepted episodes kept in a bounded min-heap.
        # Each item: ((score, raw, velocity, id), episode_dict)
        self.ranked_limit = config.ranked_limit if config.ranked_limit and config.ranked_limit > 0 else 10000
        self.top_ranked: List[Tuple[Tuple[float, float, float, int], Dict[str, Any]]] = []

    def update_observed_time(self, ts: int) -> None:
        self.observed_min_ts = ts if self.observed_min_ts is None else min(self.observed_min_ts, ts)
        self.observed_max_ts = ts if self.observed_max_ts is None else max(self.observed_max_ts, ts)

    def _update_top_ranked(self, ep_dict: Dict[str, Any]) -> None:
        key = (
            float(ep_dict.get("score", 0.0)),
            float(ep_dict.get("raw_score", 0.0)),
            float(ep_dict.get("fanout_velocity_score", 0.0)),
            int(ep_dict.get("id", 0)),
        )
        item = (key, ep_dict)
        if self.ranked_limit <= 0:
            return
        if len(self.top_ranked) < self.ranked_limit:
            heapq.heappush(self.top_ranked, item)
        elif key > self.top_ranked[0][0]:
            heapq.heapreplace(self.top_ranked, item)

    def _update_validation_for_episode(self, ep: Any, matches_fh) -> None:
        ep_dict_small = None
        for idx, rt in enumerate(self.redteam):
            rt_time = rt["time"]
            rt_source = rt["source"]
            rt_dest = rt["dest"]
            rt_user = rt["user"]
            if ep.source != rt_source:
                continue
            if rt_dest not in ep.destinations:
                continue
            if not (ep.start_time - self.config.validation_window <= rt_time <= ep.end_time + self.config.validation_window):
                continue

            rt_key = (rt_time, rt_user, rt_source, rt_dest)
            self.matched_redteam.add(rt_key)
            self.matched_episode_ids.add(ep.id)
            self.match_gate_counts[ep.candidate_gate] += 1
            self.matched_episode_gate_by_id[ep.id] = ep.candidate_gate

            exact = rt_time == ep.start_time
            if exact:
                self.exact_start_redteam.add(rt_key)
                self.exact_start_gate_counts[ep.candidate_gate] += 1

            if ep_dict_small is None:
                ep_dict_small = episode_to_dict(ep, sample_limit=30)

            redteam_in_observed = False
            if self.observed_min_ts is not None and self.observed_max_ts is not None:
                redteam_in_observed = self.observed_min_ts <= rt_time <= self.observed_max_ts

            match = {
                "redteam_index": idx,
                "redteam": rt,
                "episode": ep_dict_small,
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
                "exact_start_match": exact,
                "redteam_in_observed_time_range": redteam_in_observed,
            }
            matches_fh.write(json.dumps(match) + "\n")

    def flush_detector_buffers(self, paths: Dict[str, Path], near_match_limit: int = 500) -> None:
        """Write newly finalized episodes and clear detector buffers before checkpointing."""
        accepted = self.detector.completed
        suppressed = self.detector.suppressed
        if not accepted and not suppressed:
            return

        with open(paths["accepted"], "a", encoding="utf-8") as accepted_fh, \
             open(paths["suppressed"], "a", encoding="utf-8") as suppressed_fh, \
             open(paths["matches"], "a", encoding="utf-8") as matches_fh, \
             open(paths["near"], "a", encoding="utf-8") as near_fh:

            if accepted:
                accepted_summary = summarize_episodes(accepted)
                self.accepted_signal_counts.update(accepted_summary["signals"])
                self.accepted_gate_counts.update(accepted_summary["gates"])

                for ep in accepted:
                    ep_dict = episode_to_dict(ep)
                    accepted_fh.write(json.dumps(ep_dict) + "\n")
                    self._update_top_ranked(ep_dict)
                    self._update_validation_for_episode(ep, matches_fh)
                self.accepted_count += len(accepted)

            if suppressed:
                suppressed_summary = summarize_episodes(suppressed)
                self.suppressed_signal_counts.update(suppressed_summary["signals"])
                self.suppressed_gate_counts.update(suppressed_summary["gates"])
                self.suppressed_reason_counts.update(suppressed_summary["suppression_reasons"])
                self.suppressed_entropy_counts.update(suppressed_summary["entropy_signals"])

                for ep in suppressed:
                    suppressed_fh.write(json.dumps(episode_to_dict(ep)) + "\n")
                self.suppressed_count += len(suppressed)

                remaining = max(0, near_match_limit - self.near_match_written)
                if remaining > 0:
                    near_matches = find_suppressed_near_matches(
                        suppressed,
                        self.redteam,
                        self.config.validation_window,
                        self.observed_min_ts,
                        self.observed_max_ts,
                        limit=remaining,
                    )
                    for item in near_matches:
                        near_fh.write(json.dumps(item) + "\n")
                    self.near_match_written += len(near_matches)

        # Critical for checkpoint size.
        self.detector.completed = []
        self.detector.suppressed = []
        self.updated_at = time.time()

    def validation_snapshot(self) -> Dict[str, Any]:
        redteam_observed = []
        if self.observed_min_ts is not None and self.observed_max_ts is not None:
            redteam_observed = [
                rt for rt in self.redteam
                if self.observed_min_ts <= rt["time"] <= self.observed_max_ts
            ]
        matched_observed = {
            key for key in self.matched_redteam
            if self.observed_min_ts is not None
            and self.observed_max_ts is not None
            and self.observed_min_ts <= key[0] <= self.observed_max_ts
        }
        return {
            "total_redteam": len(self.redteam),
            "matched_redteam": len(self.matched_redteam),
            "recall_all": len(self.matched_redteam) / len(self.redteam) if self.redteam else 0.0,
            "total_redteam_in_observed_range": len(redteam_observed),
            "matched_redteam_in_observed_range": len(matched_observed),
            "recall_observed_range": len(matched_observed) / len(redteam_observed) if redteam_observed else 0.0,
            "redteam_outside_observed_range": max(0, len(self.redteam) - len(redteam_observed)),
            "observed_time_range": f"{self.observed_min_ts} - {self.observed_max_ts}",
            "total_episodes": self.accepted_count,
            "matched_episodes": len(self.matched_episode_ids),
            "episode_overlap_rate": len(self.matched_episode_ids) / self.accepted_count if self.accepted_count else 0.0,
            "exact_start_matches": len(self.exact_start_redteam),
            "match_candidate_gates": dict(self.match_gate_counts),
            "exact_start_candidate_gates": dict(self.exact_start_gate_counts),
            "matched_episode_candidate_gates": dict(Counter(self.matched_episode_gate_by_id.values())),
        }


def build_config(args: argparse.Namespace) -> Config:
    return Config(
        episode_window=args.episode_window,
        validation_window=args.validation_window,
        warmup_events=args.warmup,
        min_score=args.min_score,
        gate_a_novelty_threshold=args.gate_a_novelty_threshold,
        gate_a_max_duration=args.gate_a_max_duration,
        gate_a_max_destinations=args.gate_a_max_destinations,
        gate_d_novelty_threshold=args.gate_d_novelty_threshold,
        gate_e_novelty_threshold=args.gate_e_novelty_threshold,
        gate_e_noncompact_novelty_threshold=args.gate_e_noncompact_novelty_threshold,
        gate_e_max_duration=args.gate_e_max_duration,
        gate_e_max_destinations=args.gate_e_max_destinations,
        velocity_window=args.velocity_window,
        velocity_min_new_destinations=args.velocity_min_new_destinations,
        gate_b_velocity_threshold=args.gate_b_velocity_threshold,
        low_novelty_ratio=args.low_novelty_ratio,
        suppress_low_novelty_without_velocity=args.enable_low_novelty_suppression,
        enable_gate_d=args.enable_gate_d,
        enable_gate_e=args.enable_gate_e,
        ranked_limit=args.ranked_limit,
    )


def output_paths(out: Path) -> Dict[str, Path]:
    return {
        "accepted": out / "episodes_v036_accepted.jsonl",
        "ranked": out / "episodes_v036_ranked_top.jsonl",
        "suppressed": out / "episodes_v036_suppressed.jsonl",
        "matches": out / "redteam_matches_v036.jsonl",
        "near": out / "redteam_suppressed_near_matches_v036.jsonl",
        "report": out / "validation_report_v036.txt",
        "checkpoint": out / "checkpoint_v036.pkl",
    }


def save_checkpoint(path: Path, state: StreamingRunState) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        pickle.dump(state, fh, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)


def load_checkpoint(path: Path) -> StreamingRunState:
    with open(path, "rb") as fh:
        return pickle.load(fh)


def write_ranked_file(paths: Dict[str, Path], state: StreamingRunState) -> None:
    ranked = sorted(state.top_ranked, key=lambda item: item[0], reverse=True)
    with open(paths["ranked"], "w", encoding="utf-8") as fh:
        for _, ep_dict in ranked:
            fh.write(json.dumps(ep_dict) + "\n")


def write_report(paths: Dict[str, Path], state: StreamingRunState, invocation_elapsed: Optional[float] = None) -> None:
    snap = state.validation_snapshot()
    precision_proxy = snap["matched_episodes"] / snap["total_episodes"] if snap["total_episodes"] else 0.0

    lines: List[str] = []
    lines.append("SRIA RT v0.3.6 Stateful Batch Runner")
    lines.append("=" * 80)
    lines.append("Purpose: run v0.3.5 scoring in safe resumable batches while preserving detector memory.")
    lines.append("NOTE: redteam.txt is used only for sparse-window selection and post-hoc validation.")
    lines.append("NOTE: Detector scoring does NOT use redteam source/destination/user labels.")
    lines.append("")
    lines.append("Run progress:")
    lines.append(f"  batch_index: {state.batch_index}")
    lines.append(f"  byte_offset: {state.byte_offset}")
    lines.append(f"  scanned_lines: {state.scanned_lines}")
    lines.append(f"  candidate_events_in_sparse_windows: {state.candidate_events}")
    lines.append(f"  auth_time_observed: {state.observed_min_ts} - {state.observed_max_ts}")
    lines.append(f"  accepted_episodes_written: {state.accepted_count}")
    lines.append(f"  suppressed_episodes_written: {state.suppressed_count}")
    lines.append(f"  active_episodes_in_memory: {len(state.detector.active)}")
    lines.append(f"  next_episode_id: {state.detector.next_id}")
    lines.append(f"  finished: {state.finished}")
    if invocation_elapsed is not None:
        lines.append(f"  last_invocation_elapsed_seconds: {invocation_elapsed:.1f}")
    lines.append("")
    lines.append("Validation - all redteam events:")
    lines.append(f"  total_redteam: {snap['total_redteam']}")
    lines.append(f"  matched_redteam: {snap['matched_redteam']}")
    lines.append(f"  recall_all: {snap['recall_all']:.4f}")
    lines.append(f"  exact_start_matches: {snap['exact_start_matches']}")
    lines.append("")
    lines.append("Validation - observed auth time range only:")
    lines.append(f"  observed_time_range: {snap['observed_time_range']}")
    lines.append(f"  total_redteam_in_observed_range: {snap['total_redteam_in_observed_range']}")
    lines.append(f"  matched_redteam_in_observed_range: {snap['matched_redteam_in_observed_range']}")
    lines.append(f"  recall_observed_range: {snap['recall_observed_range']:.4f}")
    lines.append(f"  redteam_outside_observed_range: {snap['redteam_outside_observed_range']}")
    lines.append("")
    lines.append("Episode precision proxy:")
    lines.append(f"  total_episodes: {snap['total_episodes']}")
    lines.append(f"  matched_episodes: {snap['matched_episodes']}")
    lines.append(f"  episode_overlap_rate: {snap['episode_overlap_rate']:.8f}")
    lines.append(f"  precision_proxy_matched_episodes_over_total: {precision_proxy:.8f}")
    lines.append("")
    lines.append("Matched redteam candidate gates:")
    for gate, count in Counter(snap.get("match_candidate_gates", {})).most_common():
        lines.append(f"  {gate}: {count}")
    lines.append("")
    lines.append("Matched episode candidate gates:")
    for gate, count in Counter(snap.get("matched_episode_candidate_gates", {})).most_common():
        lines.append(f"  {gate}: {count}")
    lines.append("")
    lines.append("Exact-start candidate gates:")
    for gate, count in Counter(snap.get("exact_start_candidate_gates", {})).most_common():
        lines.append(f"  {gate}: {count}")
    lines.append("")
    lines.append("Episode shaping configuration:")
    cfg = state.config
    for k, v in asdict(cfg).items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Accepted candidate gates:")
    for gate, count in state.accepted_gate_counts.most_common(25):
        lines.append(f"  {gate}: {count}")
    lines.append("")
    lines.append("Accepted top signals:")
    for sig, count in state.accepted_signal_counts.most_common(30):
        lines.append(f"  {sig}: {count}")
    lines.append("")
    lines.append("Suppressed episodes:")
    lines.append(f"  total_suppressed: {state.suppressed_count}")
    for reason, count in state.suppressed_reason_counts.most_common(25):
        lines.append(f"  {reason}: {count}")
    lines.append("")
    lines.append("Suppressed entropy signals:")
    for sig, count in state.suppressed_entropy_counts.most_common(25):
        lines.append(f"  {sig}: {count}")
    lines.append("")
    lines.append("Suppressed redteam near-match diagnostics:")
    lines.append(f"  suppressed_near_matches_written: {state.near_match_written}")
    lines.append("  NOTE: diagnostic only; redteam labels are not used by scoring.")
    paths["report"].write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--base-dir", default=".")
    p.add_argument("--out-dir", default="v036_batches")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force-start", action="store_true")
    p.add_argument("--finish", action="store_true", help="finalize active episodes immediately after this invocation")

    # In v036 this means additional candidate events to process in this invocation.
    p.add_argument("--max-candidate-events", type=int, default=5_000_000)
    p.add_argument("--max-lines", type=int, default=0, help="additional auth.txt lines to scan this invocation; 0=no limit")
    p.add_argument("--checkpoint-every-candidates", type=int, default=1_000_000)
    p.add_argument("--near-match-limit", type=int, default=500)

    p.add_argument("--window", type=int, default=600)
    p.add_argument("--episode-window", type=int, default=300)
    p.add_argument("--validation-window", type=int, default=600)
    p.add_argument("--warmup", type=int, default=50_000)
    p.add_argument("--min-score", type=float, default=0.78)

    # Same tuning knobs as v035.
    p.add_argument("--gate-a-novelty-threshold", type=float, default=0.25)
    p.add_argument("--gate-a-max-duration", type=int, default=900)
    p.add_argument("--gate-a-max-destinations", type=int, default=24)
    p.add_argument("--gate-d-novelty-threshold", type=float, default=0.20)
    p.add_argument("--gate-e-novelty-threshold", type=float, default=0.20)
    p.add_argument("--gate-e-noncompact-novelty-threshold", type=float, default=0.35)
    p.add_argument("--gate-e-max-duration", type=int, default=720)
    p.add_argument("--gate-e-max-destinations", type=int, default=20)
    p.add_argument("--velocity-window", type=int, default=120)
    p.add_argument("--velocity-min-new-destinations", type=int, default=3)
    p.add_argument("--gate-b-velocity-threshold", type=float, default=0.60)
    p.add_argument("--low-novelty-ratio", type=float, default=0.25)
    p.add_argument("--enable-low-novelty-suppression", action="store_true")
    p.add_argument("--enable-gate-d", action="store_true")
    p.add_argument("--enable-gate-e", action="store_true")
    p.add_argument("--ranked-limit", type=int, default=10000)
    return p.parse_args()


def initialize_or_resume(args: argparse.Namespace, paths: Dict[str, Path]) -> StreamingRunState:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ckpt = paths["checkpoint"]

    if args.resume:
        if not ckpt.exists():
            raise FileNotFoundError(f"Cannot resume; checkpoint not found: {ckpt}")
        state = load_checkpoint(ckpt)
        print(f"[resume] Loaded checkpoint: {ckpt}")
        print(f"[resume] byte_offset={state.byte_offset:,} scanned_lines={state.scanned_lines:,} candidate_events={state.candidate_events:,}")
        return state

    if ckpt.exists() and not args.force_start:
        raise RuntimeError(
            f"Checkpoint already exists: {ckpt}. Use --resume to continue or --force-start to overwrite."
        )

    # Fresh run: truncate output files.
    for key in ["accepted", "ranked", "suppressed", "matches", "near", "report"]:
        paths[key].parent.mkdir(parents=True, exist_ok=True)
        paths[key].write_text("", encoding="utf-8")

    base = Path(args.base_dir)
    redteam = load_redteam(base / "redteam.txt")
    windows = merge_windows(redteam, args.window)
    config = build_config(args)
    state = StreamingRunState(config, windows, redteam)
    save_checkpoint(ckpt, state)
    print(f"[start] Created fresh checkpoint: {ckpt}")
    return state


def main() -> None:
    args = parse_args()
    base = Path(args.base_dir)
    out = Path(args.out_dir)
    paths = output_paths(out)
    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    if not auth_file.exists():
        raise FileNotFoundError(f"Missing auth file: {auth_file}")

    print("=" * 80)
    print("SRIA RT v0.3.6 - Stateful Batch Runner")
    print("=" * 80)
    print(f"Base dir: {base}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Out dir: {out}")
    print(f"Batch candidate limit this invocation: {args.max_candidate_events:,}" if args.max_candidate_events else "Batch candidate limit this invocation: none")
    print("NOTE: redteam.txt is used only for sparse-window selection and post-hoc validation.")
    print("NOTE: Detector scoring DOES NOT use redteam source/destination/user labels.")
    print("=" * 80)

    state = initialize_or_resume(args, paths)
    print(f"[validation] Loaded redteam events: {len(state.redteam)}")
    if state.redteam:
        print(f"[validation] Redteam time range: {min(r['time'] for r in state.redteam)} - {max(r['time'] for r in state.redteam)}")
    print(f"[validation] Merged sparse windows: {len(state.windows)}")
    print(f"[validation] Total sparse seconds: {sum(b - a for a, b in state.windows):,}")

    invocation_start = time.time()
    invocation_candidates = 0
    invocation_lines = 0
    next_checkpoint_at = args.checkpoint_every_candidates if args.checkpoint_every_candidates > 0 else 0

    if state.finished:
        print("[status] This run is already marked finished. Nothing to process.")
        write_report(paths, state, 0.0)
        return

    print("\n[detection] Streaming auth.txt from saved byte offset...")

    with open(auth_file, "rb") as fh:
        fh.seek(state.byte_offset)
        while True:
            raw = fh.readline()
            if not raw:
                print("  Reached EOF.")
                state.finished = True
                break

            state.byte_offset = fh.tell()
            state.scanned_lines += 1
            invocation_lines += 1

            if args.max_lines and invocation_lines > args.max_lines:
                print("  Reached max lines for this invocation. Checkpointing.")
                break

            try:
                line = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            parsed = parse_auth_line(line)
            if not parsed:
                continue

            ts = parsed["time"]
            state.update_observed_time(ts)

            if state.windows:
                inside, state.pointer = in_windows(ts, state.windows, state.pointer)
                if not inside:
                    continue

            state.candidate_events += 1
            invocation_candidates += 1
            state.detector.process(parsed)

            if invocation_candidates % 1_000_000 == 0:
                elapsed = max(0.001, time.time() - invocation_start)
                print(
                    f"  invocation_candidates={invocation_candidates:,} "
                    f"total_candidates={state.candidate_events:,} "
                    f"scanned_lines={state.scanned_lines:,} "
                    f"rate={invocation_candidates / elapsed:,.0f} candidate/sec"
                )

            if next_checkpoint_at and invocation_candidates >= next_checkpoint_at:
                state.flush_detector_buffers(paths, near_match_limit=args.near_match_limit)
                save_checkpoint(paths["checkpoint"], state)
                write_ranked_file(paths, state)
                write_report(paths, state, time.time() - invocation_start)
                print(f"  [checkpoint] saved at invocation_candidates={invocation_candidates:,} total_candidates={state.candidate_events:,}")
                next_checkpoint_at += args.checkpoint_every_candidates

            if args.max_candidate_events and invocation_candidates >= args.max_candidate_events:
                print("  Reached batch candidate limit for this invocation. Checkpointing.")
                break

    if args.finish or state.finished:
        print("\n[finish] Finalizing active episodes...")
        episodes, suppressed = state.detector.finish()
        # detector.finish returns the same internal buffers; flush will write and clear them.
        state.flush_detector_buffers(paths, near_match_limit=args.near_match_limit)
        state.finished = True
    else:
        state.flush_detector_buffers(paths, near_match_limit=args.near_match_limit)

    state.batch_index += 1
    state.updated_at = time.time()
    elapsed = time.time() - invocation_start
    save_checkpoint(paths["checkpoint"], state)
    write_ranked_file(paths, state)
    write_report(paths, state, elapsed)

    snap = state.validation_snapshot()
    print("\n[detection] Batch complete")
    print(f"  invocation_candidates: {invocation_candidates:,}")
    print(f"  invocation_lines: {invocation_lines:,}")
    print(f"  total_scanned_lines: {state.scanned_lines:,}")
    print(f"  total_candidate_events_in_sparse_windows: {state.candidate_events:,}")
    print(f"  auth_time_observed: {state.observed_min_ts} - {state.observed_max_ts}")
    print(f"  accepted_episodes_written: {state.accepted_count:,}")
    print(f"  suppressed_episodes_written: {state.suppressed_count:,}")
    print(f"  active_episodes_in_memory: {len(state.detector.active):,}")
    print(f"  matched_redteam: {snap['matched_redteam']} / {snap['total_redteam']}")
    print(f"  matched_redteam_in_observed_range: {snap['matched_redteam_in_observed_range']} / {snap['total_redteam_in_observed_range']}")
    print(f"  exact_start_matches: {snap['exact_start_matches']}")
    print(f"  elapsed: {elapsed:.1f}s")
    print("\n[output]")
    print(f"  Accepted episodes: {paths['accepted']}")
    print(f"  Ranked top episodes: {paths['ranked']}")
    print(f"  Suppressed episodes: {paths['suppressed']}")
    print(f"  Matches: {paths['matches']}")
    print(f"  Suppressed near matches: {paths['near']}")
    print(f"  Report: {paths['report']}")
    print(f"  Checkpoint: {paths['checkpoint']}")
    print("=" * 80)


if __name__ == "__main__":
    main()
