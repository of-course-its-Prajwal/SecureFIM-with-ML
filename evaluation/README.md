# SecureFIM Pro — Evaluation Harness

Reproducible measurement of detection performance, producing the confusion
matrices and metrics required for the Findings chapter (RQ1 / H1 / H2).

## How to run

From the project root, with the virtual environment active:

```
pip install matplotlib
python -m evaluation.run_evaluation --benign 400 --attack 160
```

Optional flags: `--threshold 70` (alert threshold), `--seed 42` (reproducibility).

Outputs land in `evaluation/results/`:

| File | Purpose |
|---|---|
| `metrics_comparison.csv` | Headline table — Accuracy / Precision / Recall / F1 / FPR |
| `per_scenario_recall.csv` | Detection rate per attack type, rules-only vs full system |
| `threshold_sweep.csv` | Performance across alert thresholds |
| `figures/*.png` | Charts for the Findings chapter |

The harness writes its trained SVM to `evaluation/_model_cache/` and therefore
**never overwrites the production model** in `models/`.

## Methodology

**Unit of classification.** The classified unit is an *event window* — a burst
of file activity — not an individual event. This mirrors how the One-Class SVM
operates in production (`server/ml.extract_features` consumes windows), so the
evaluation measures the deployed system rather than a proxy for it.

**Data.** Entirely synthetic. Windows are generated for five benign activity
patterns and eight attack patterns modelled on the District Administration
Office context (citizenship, land, voter and tax records). No real citizen data
is used at any point.

**Benign classes include deliberately hard cases.** A legitimate bulk import of
scanned records (high event rate, high burst score) and legitimate edits to
HIGH-sensitivity records during office hours are both included. Without these,
the false-positive rate would be an artefact of an easy dataset and the
evaluation would be meaningless.

**Attack classes include deliberately evasive cases.** Three attacks are
designed specifically to defeat the rule engine:

- *in-place encryption* — no renamed extension, no ransom note, executed during
  office hours, so every signature and time-of-day rule is bypassed;
- *slow-drip deletion* — deletions spread thinly so the mass-deletion thresholds
  never trip;
- *stealth tampering* — two or three record edits at normal pace during office
  hours, near-indistinguishable from legitimate work.

**Training protocol.** The One-Class SVM is trained on **benign windows only**,
which is the methodologically correct protocol for one-class learning: the model
learns the boundary of normal behaviour and never sees an attack during
training. Attacks appear only at test time. Half the benign windows are held out
for testing alongside all attack windows.

**Configurations compared.**

| Config | Description | Role |
|---|---|---|
| A | Checksum-only — alerts on any integrity change | Classical FIM baseline (H1) |
| B | SecureFIM Pro with the ML detector disabled | Rule-based baseline (H2) |
| C | SecureFIM Pro as deployed — rules + One-Class SVM | System under test |

Configurations B and C import the production modules (`server.ransomware`,
`server.features`, `server.ml`) directly, so the evaluation exercises the real
detection logic rather than a reimplementation of it.

## Known limitations of this evaluation

- The dataset is synthetic; real office activity would be noisier and more
  varied, and performance on live data may differ.
- Detection latency is measured separately, against the live system, and is not
  part of this offline harness.
- No expert-analyst comparison is included, as no security professionals were
  available to this study. Claims about expert agreement have therefore been
  removed rather than estimated.
- The ransomware detector's 120-second sliding window is reset per test window,
  which is correct for independent windows but does not capture cross-window
  campaigns.
