# SRIA RT v0.4.0 Baseline Runbook

## Goal

Stop hand-tuning gates temporarily and test whether simple learned baselines outperform the SRIA gate score on the existing engineered episode features.

This does **not** rescan `auth.txt`. It uses existing JSONL outputs from:

- `v033_full`
- `v036_batches`

## Copy the script

Place this file in:

```cmd
F:\SRIA\SRIA_RT_v01\sria_rt_v040_baseline_eval.py
```

## First run: v033 recall-heavy branch

Run this first:

```cmd
cd /d F:\SRIA\SRIA_RT_v01

py sria_rt_v040_baseline_eval.py --base-dir . --branch v033 --include-suppressed --negative-sample 300000
```

Then read the summary:

```cmd
powershell -NoProfile -Command "Get-Content .\v040_baselines_v033\baseline_summary_v033.txt -Tail 200"
```

## Second run: v036 precision-pruned branch

Run this after v033:

```cmd
py sria_rt_v040_baseline_eval.py --base-dir . --branch v036 --include-suppressed --negative-sample 300000
```

Then read the summary:

```cmd
powershell -NoProfile -Command "Get-Content .\v040_baselines_v036\baseline_summary_v036.txt -Tail 200"
```

## Larger negative sample, optional

If the first run finishes easily, repeat with a larger suppressed-negative sample:

```cmd
py sria_rt_v040_baseline_eval.py --base-dir . --branch v033 --include-suppressed --negative-sample 1000000 --out-dir v040_baselines_v033_1Mneg
```

Then:

```cmd
powershell -NoProfile -Command "Get-Content .\v040_baselines_v033_1Mneg\baseline_summary_v033.txt -Tail 200"
```

## What to compare

Look at these sections:

- `sria_score`
- `logreg_l1`
- `logreg_l2`
- `random_forest`
- `hist_gradient_boosting`

For each model, compare:

- Average Precision (`AP`)
- top100 redteam events hit
- top500 redteam events hit
- top1000 redteam events hit
- top5000 redteam events hit
- top10000 redteam events hit

## Interpretation

If logistic regression or random forest beats `sria_score` clearly at top-K, the hand gates are probably the wrong final architecture.

If `sria_score` competes strongly or wins, SRIA has evidence that its interpretable gate structure is doing real work.

## Important limitation

This is still a sparse-window episode/candidate evaluation. It is not deployment precision over the full negative-only population. It is the correct next diagnostic before building v0.3.7 or v0.4.1.
