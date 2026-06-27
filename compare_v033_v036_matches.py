import json
from pathlib import Path
from collections import Counter, defaultdict

V033 = Path("v033_full/redteam_matches_v033.jsonl")
V036 = Path("v036_batches/redteam_matches_v036_FINAL_SPARSE.jsonl")
OUT = Path("v037_match_comparison")
OUT.mkdir(exist_ok=True)

def load_matches(path):
    matches = []
    seen_redteam = set()
    by_redteam = defaultdict(list)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            idx = obj.get("redteam_index")
            rt = obj.get("redteam", {})
            ep = obj.get("episode", {})
            gate = ep.get("candidate_gate", "")
            key = (
                idx,
                rt.get("time"),
                rt.get("user"),
                rt.get("source"),
                rt.get("dest"),
            )
            seen_redteam.add(key)
            by_redteam[key].append(obj)
            matches.append(obj)

    return matches, seen_redteam, by_redteam

m33, s33, by33 = load_matches(V033)
m36, s36, by36 = load_matches(V036)

caught_both = s33 & s36
lost_by_v036 = s33 - s36
new_in_v036 = s36 - s33

def gate_counter(keys, by):
    c = Counter()
    for key in keys:
        for obj in by[key]:
            gate = obj.get("episode", {}).get("candidate_gate", "UNKNOWN")
            c[gate] += 1
    return c

lost_gate_counts = gate_counter(lost_by_v036, by33)
kept_gate_counts_v033 = gate_counter(caught_both, by33)
kept_gate_counts_v036 = gate_counter(caught_both, by36)

summary = []
summary.append("SRIA v033 vs v036 Match Comparison")
summary.append("=" * 80)
summary.append(f"v033 unique matched redteam: {len(s33)}")
summary.append(f"v036 unique matched redteam: {len(s36)}")
summary.append(f"caught by both: {len(caught_both)}")
summary.append(f"caught by v033 but lost by v036: {len(lost_by_v036)}")
summary.append(f"caught by v036 but not v033: {len(new_in_v036)}")
summary.append("")
summary.append("Lost-by-v036 gate counts from v033:")
for gate, count in lost_gate_counts.most_common():
    summary.append(f"  {gate}: {count}")
summary.append("")
summary.append("Kept-by-both gate counts in v033:")
for gate, count in kept_gate_counts_v033.most_common():
    summary.append(f"  {gate}: {count}")
summary.append("")
summary.append("Kept-by-both gate counts in v036:")
for gate, count in kept_gate_counts_v036.most_common():
    summary.append(f"  {gate}: {count}")

(OUT / "comparison_summary.txt").write_text("\n".join(summary), encoding="utf-8")

def write_jsonl(path, keys, by):
    with path.open("w", encoding="utf-8") as f:
        for key in sorted(keys):
            for obj in by[key]:
                f.write(json.dumps(obj, sort_keys=True) + "\n")

write_jsonl(OUT / "lost_by_v036_from_v033.jsonl", lost_by_v036, by33)
write_jsonl(OUT / "caught_by_both_v033_view.jsonl", caught_both, by33)
write_jsonl(OUT / "caught_by_both_v036_view.jsonl", caught_both, by36)
write_jsonl(OUT / "new_in_v036_not_v033.jsonl", new_in_v036, by36)

print("\n".join(summary))
print("")
print(f"Wrote outputs to: {OUT}")