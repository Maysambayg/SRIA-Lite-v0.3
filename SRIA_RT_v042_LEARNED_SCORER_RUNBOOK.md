# SRIA RT v0.4.2 Learned Scorer Export Runbook

## Purpose

`SRIA RT v0.4.2` moves the project from hand-tuned gate scoring to a leakage-stripped learned scorer export.

It does **not** rescan `auth.txt`. It consumes the existing v033/v036 episode outputs.

The script trains learned rankers using only upstream engineered episode features:

- `duration`
- `events_count`
- `destination_count`
- `novelty_ratio`
- `compactness_score`
- `fanout_velocity_score`
- `peak_velocity_new_dests`
- primitive `sig__...` indicators

It intentionally drops:

- `score`
- `raw_score`
- `entropy_penalty`
- `max_risk`
- all `gate__*` outputs
- `candidate_gate` as an ML input

So this continues the clean v0.4.1 methodology.

## Install requirements

You already installed these, but this is the fallback command:

```cmd
py -m pip install numpy scikit-learn joblib
```

## Step 1 — copy the script

Copy this file into:

```cmd
F:\SRIA\SRIA_RT_v01
```

File:

```text
sria_rt_v042_learned_scorer_export.py
```

Then enter the folder:

```cmd
cd /d F:\SRIA\SRIA_RT_v01
```

## Step 2 — train on v033 and rank v033 accepted episodes

This is the first canonical export run because v033 has more positive examples than v036.

```cmd
py sria_rt_v042_learned_scorer_export.py --base-dir . --train-branch v033 --score-branch v033 --include-suppressed --negative-sample 100000 --sample-mode reservoir --models sgd_cw_none,tree_depth6_cw_none --score-set accepted --out-dir v042_train_v033_score_v033
```

Inspect the report:

```cmd
powershell -NoProfile -Command "Get-Content .\v042_train_v033_score_v033\v042_export_report_train_v033_score_v033.txt -Tail 220"
```

## Step 3 — train on v033 and rank v036 accepted episodes

This is the first cross-branch sanity check.

```cmd
py sria_rt_v042_learned_scorer_export.py --base-dir . --train-branch v033 --score-branch v036 --include-suppressed --negative-sample 100000 --sample-mode reservoir --models sgd_cw_none,tree_depth6_cw_none --score-set accepted --out-dir v042_train_v033_score_v036
```

Inspect the report:

```cmd
powershell -NoProfile -Command "Get-Content .\v042_train_v033_score_v036\v042_export_report_train_v033_score_v036.txt -Tail 220"
```

## Step 4 — optional: train on v036 and rank v036

v036 has fewer positives, but this run tells us what a precision-pruned branch learns on itself.

```cmd
py sria_rt_v042_learned_scorer_export.py --base-dir . --train-branch v036 --score-branch v036 --include-suppressed --negative-sample 100000 --sample-mode reservoir --models sgd_cw_none,tree_depth6_cw_none --score-set accepted --out-dir v042_train_v036_score_v036
```

Inspect:

```cmd
powershell -NoProfile -Command "Get-Content .\v042_train_v036_score_v036\v042_export_report_train_v036_score_v036.txt -Tail 220"
```

## Outputs

Each run writes:

```text
model_<train_branch>_<model>.joblib
ranked_<score_branch>_<model>.csv
ranked_<score_branch>_<model>_top5000.jsonl
topk_comparison_train_<train_branch>_score_<score_branch>.csv
v042_export_report_train_<train_branch>_score_<score_branch>.txt
```

## How to read the result

Use the ranked CSV files as review queues.

The two most useful output files are usually:

```text
ranked_v033_sgd_cw_none.csv
ranked_v033_tree_depth6_cw_none.csv
```

or, for cross-branch scoring:

```text
ranked_v036_sgd_cw_none.csv
ranked_v036_tree_depth6_cw_none.csv
```

## Important interpretation boundary

If `train_branch == score_branch`, this is **not held-out validation**. It is a trained scorer export and review-queue generation.

The honest validation evidence remains v0.4.1 redteam-group split.

The v0.4.2 purpose is operationalization of the new direction:

```text
SRIA feature engine + learned ranker + interpretable report
```

not another hand-gate tuning branch.
