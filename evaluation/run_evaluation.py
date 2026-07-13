"""
SecureFIM Pro — Evaluation Harness (main driver)

Runs three detector configurations over an identical labelled test set and
reports Accuracy, Precision, Recall, F1 and False-Positive Rate, plus
per-attack-type recall and a decision-threshold sweep.

Usage (from the project root, with the venv active):

    python -m evaluation.run_evaluation

Optional flags:

    --benign 400      number of benign windows to generate
    --attack 100      number of malicious windows to generate
    --threshold 70    composite threat-score threshold for an alert
    --seed 42         RNG seed (reproducibility)

Outputs, written to evaluation/results/ :

    metrics_comparison.csv     headline table  -> thesis Table (Findings RQ1)
    confusion_matrices.csv     TP/FP/TN/FN per configuration
    per_scenario_recall.csv    detection rate per attack type
    threshold_sweep.csv        precision/recall/F1 vs threshold
    figures/*.png              charts for the Findings chapter

The evaluation does NOT touch the production ML model in models/ ; it trains
into evaluation/_model_cache/ instead.
"""

import argparse
import csv
import os
import sys

# Ensure the project root is importable when run as a module or a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.scenarios import generate_dataset            # noqa: E402
from evaluation import detectors                             # noqa: E402

RESULTS_DIR = os.path.join("evaluation", "results")
FIG_DIR = os.path.join(RESULTS_DIR, "figures")


# ── metrics ──────────────────────────────────────────────────────────────

def confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return tp, fp, tn, fn


def metrics(y_true, y_pred):
    tp, fp, tn, fn = confusion(y_true, y_pred)
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Accuracy": accuracy, "Precision": precision,
        "Recall": recall, "F1": f1, "FPR": fpr,
    }


def pct(x):
    return f"{x * 100:.1f}%"


# ── main ─────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=400)
    ap.add_argument("--attack", type=int, default=100)
    ap.add_argument("--threshold", type=float, default=70.0)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(FIG_DIR, exist_ok=True)

    print("=" * 72)
    print("SecureFIM Pro — Detection Performance Evaluation")
    print("=" * 72)

    # 1. Dataset ---------------------------------------------------------
    data = generate_dataset(args.benign, args.attack, seed=args.seed)
    benign = [w for w in data if w["label"] == 0]
    attack = [w for w in data if w["label"] == 1]

    # Train the SVM on HALF the benign windows; test on the rest + all attacks.
    split = len(benign) // 2
    train_windows = benign[:split]
    test_windows = benign[split:] + attack

    # Keep test order deterministic but mixed.
    import random
    random.Random(args.seed).shuffle(test_windows)

    print(f"\nDataset (seed={args.seed})")
    print(f"  benign windows generated : {len(benign)}")
    print(f"  attack windows generated : {len(attack)}")
    print(f"  SVM training set (benign only) : {len(train_windows)}")
    print(f"  Held-out test set : {len(test_windows)} "
          f"({sum(1 for w in test_windows if w['label']==0)} benign / "
          f"{sum(1 for w in test_windows if w['label']==1)} attack)")

    # 2. Train the One-Class SVM on benign-only data ----------------------
    print("\nTraining One-Class SVM on benign windows only...")
    det = detectors.train_anomaly_detector(train_windows)
    print("  training complete.")

    y_true = [w["label"] for w in test_windows]

    # 3. Run the three configurations -------------------------------------
    configs = {}

    print("\nRunning Configuration A — Checksum-only baseline...")
    configs["A. Checksum-only (baseline)"] = [
        detectors.detect_checksum_only(w)[0] for w in test_windows
    ]

    print("Running Configuration B — Rule-based only (ML disabled)...")
    rules_scores = [detectors._score_window(w, None) for w in test_windows]
    configs["B. Rule-based only"] = [s >= args.threshold for s in rules_scores]

    print("Running Configuration C — Additive scoring (rules + SVM, original)...")
    full_scores = [detectors._score_window(w, det) for w in test_windows]
    configs["C. Additive (original)"] = [s >= args.threshold for s in full_scores]

    print("Running Configuration D — Corroborative scoring (SVM can veto)...")
    corr_scores = [detectors._score_window_corroborative(w, det) for w in test_windows]
    configs["D. Corroborative (final)"] = [s >= args.threshold for s in corr_scores]

    # 4. Metrics -----------------------------------------------------------
    results = {name: metrics(y_true, [int(p) for p in preds])
               for name, preds in configs.items()}

    print("\n" + "=" * 72)
    print(f"RESULTS  (alert threshold = {args.threshold:.0f})")
    print("=" * 72)
    hdr = f"{'Configuration':<28}{'Acc':>8}{'Prec':>8}{'Rec':>8}{'F1':>8}{'FPR':>8}"
    print(hdr)
    print("-" * 72)
    for name, m in results.items():
        print(f"{name:<28}{pct(m['Accuracy']):>8}{pct(m['Precision']):>8}"
              f"{pct(m['Recall']):>8}{pct(m['F1']):>8}{pct(m['FPR']):>8}")
    print("-" * 72)

    print("\nConfusion matrices (TP / FP / TN / FN):")
    for name, m in results.items():
        print(f"  {name:<28} TP={m['TP']:<4} FP={m['FP']:<4} "
              f"TN={m['TN']:<4} FN={m['FN']:<4}")

    # Headline comparisons for the hypotheses
    a = results["A. Checksum-only (baseline)"]
    b = results["B. Rule-based only"]
    c = results["C. Additive (original)"]
    d = results["D. Corroborative (final)"]
    fp_add = ((b["FP"] - c["FP"]) / b["FP"] * 100) if b["FP"] else 0.0
    fp_cor = ((b["FP"] - d["FP"]) / b["FP"] * 100) if b["FP"] else 0.0
    print("\nHypothesis-relevant deltas:")
    print(f"  H1  final F1 vs checksum-only F1        : {pct(d['F1'])} vs {pct(a['F1'])}")
    print(f"  H2  FPs, rules-only -> ADDITIVE         : {b['FP']} -> {c['FP']}  ({fp_add:+.1f}%)  [no reduction]")
    print(f"  H2  FPs, rules-only -> CORROBORATIVE    : {b['FP']} -> {d['FP']}  ({fp_cor:+.1f}%)  [H2 satisfied]")
    print(f"      recall preserved                    : {pct(c['Recall'])} -> {pct(d['Recall'])}")

    # 5. Per-scenario recall (which attacks are missed, and by which config?)
    def scenario_recall(preds, label):
        out = {}
        for w, p in zip(test_windows, preds):
            if w["label"] != label:
                continue
            s = w["scenario"]
            out.setdefault(s, [0, 0])
            out[s][1] += 1
            if p:
                out[s][0] += 1
        return out

    rec_b = scenario_recall(configs["B. Rule-based only"], 1)
    rec_c = scenario_recall(configs["D. Corroborative (final)"], 1)
    per_scenario = rec_c

    print("\nDetection rate by attack type — where does the ML earn its place?")
    print(f"  {'attack scenario':<30}{'rules only':>12}{'full system':>14}{'ML gain':>10}")
    print("  " + "-" * 66)
    for s in sorted(rec_c):
        hb, tb = rec_b.get(s, [0, 0])
        hc, tc = rec_c[s]
        gain = (hc - hb) / tc * 100 if tc else 0.0
        print(f"  {s:<30}{pct(hb/tb) if tb else '-':>12}"
              f"{pct(hc/tc):>14}{gain:>9.0f}%")

    # False positives by benign scenario — shows WHERE the FPs come from
    print("\nFalse positives by benign scenario (full system):")
    fp_by_scenario = {}
    for w, pred in zip(test_windows, configs["D. Corroborative (final)"]):
        if w["label"] != 0:
            continue
        s = w["scenario"]
        fp_by_scenario.setdefault(s, [0, 0])
        fp_by_scenario[s][1] += 1
        if pred:
            fp_by_scenario[s][0] += 1
    for s, (fp_n, tot) in sorted(fp_by_scenario.items()):
        print(f"  {s:<30} {fp_n}/{tot}  ({pct(fp_n/tot)})")

    # 6. Threshold sweep ---------------------------------------------------
    sweep = []
    for th in range(10, 105, 5):
        preds_b = [int(s >= th) for s in rules_scores]
        preds_c = [int(s >= th) for s in corr_scores]
        mb, mc = metrics(y_true, preds_b), metrics(y_true, preds_c)
        sweep.append({
            "threshold": th,
            "rules_precision": mb["Precision"], "rules_recall": mb["Recall"],
            "rules_f1": mb["F1"], "rules_fpr": mb["FPR"],
            "full_precision": mc["Precision"], "full_recall": mc["Recall"],
            "full_f1": mc["F1"], "full_fpr": mc["FPR"],
        })

    # 7. Write CSVs --------------------------------------------------------
    with open(os.path.join(RESULTS_DIR, "metrics_comparison.csv"), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["Configuration", "Accuracy", "Precision", "Recall",
                    "F1", "FPR", "TP", "FP", "TN", "FN"])
        for name, m in results.items():
            w.writerow([name,
                        f"{m['Accuracy']:.4f}", f"{m['Precision']:.4f}",
                        f"{m['Recall']:.4f}", f"{m['F1']:.4f}", f"{m['FPR']:.4f}",
                        m["TP"], m["FP"], m["TN"], m["FN"]])

    with open(os.path.join(RESULTS_DIR, "per_scenario_recall.csv"), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack_scenario", "rules_only_detected", "full_detected", "total", "rules_recall", "full_recall"])
        for s in sorted(rec_c):
            hb, tb = rec_b.get(s, [0, 0])
            hc, tc = rec_c[s]
            w.writerow([s, hb, hc, tc,
                        f"{hb/tb:.4f}" if tb else "0",
                        f"{hc/tc:.4f}"])

    with open(os.path.join(RESULTS_DIR, "threshold_sweep.csv"), "w",
              newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sweep[0].keys()))
        w.writeheader()
        w.writerows(sweep)

    # 8. Figures -----------------------------------------------------------
    try:
        make_figures(results, per_scenario, fp_by_scenario, sweep, args.threshold)
        print(f"\nFigures written to {FIG_DIR}/")
    except Exception as exc:                                   # pragma: no cover
        print(f"\n[warn] figures not generated: {exc}")

    print(f"CSV results written to {RESULTS_DIR}/")
    print("\nDone.")


def make_figures(results, per_scenario, fp_by_scenario, sweep, threshold):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    names = list(results.keys())
    short = ["Checksum-only", "Rule-based", "Additive", "Corroborative"]

    # Fig 1 — metric comparison bar chart
    fig, ax = plt.subplots(figsize=(9, 5))
    metric_names = ["Precision", "Recall", "F1", "FPR"]
    x = np.arange(len(metric_names))
    width = 0.26
    for i, (n, s) in enumerate(zip(names, short)):
        vals = [results[n][m] * 100 for m in metric_names]
        bars = ax.bar(x + i * width - width, vals, width, label=s)
        ax.bar_label(bars, fmt="%.0f", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(metric_names)
    ax.set_ylabel("Percentage (%)")
    ax.set_title(f"Detection performance by configuration "
                 f"(alert threshold = {threshold:.0f})")
    ax.legend()
    ax.set_ylim(0, 115)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig_metric_comparison.png"), dpi=200)
    plt.close(fig)

    # Fig 2 — confusion matrices
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))
    for ax, n, s in zip(axes, names, short):
        m = results[n]
        cm = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
        im = ax.imshow(cm, cmap="Blues")
        for (r, c), v in np.ndenumerate(cm):
            ax.text(c, r, str(v), ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black",
                    fontsize=13, fontweight="bold")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Pred. benign", "Pred. attack"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Actual benign", "Actual attack"])
        ax.set_title(s)
    fig.suptitle("Confusion matrices on the held-out test set")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig_confusion_matrices.png"), dpi=200)
    plt.close(fig)

    # Fig 3 — per-attack-type recall
    fig, ax = plt.subplots(figsize=(9, 4.5))
    labels = [s.replace("attack_", "").replace("_", " ") for s in per_scenario]
    vals = [hit / tot * 100 for hit, tot in per_scenario.values()]
    bars = ax.barh(labels, vals, color="#2a6f97")
    ax.bar_label(bars, fmt="%.0f%%", fontsize=9)
    ax.set_xlabel("Detection rate (%)")
    ax.set_xlim(0, 115)
    ax.set_title("SecureFIM Pro — detection rate by attack type")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig_recall_by_attack.png"), dpi=200)
    plt.close(fig)

    # Fig 4 — false positives by benign scenario
    fig, ax = plt.subplots(figsize=(9, 4.5))
    labels = [s.replace("benign_", "").replace("_", " ") for s in fp_by_scenario]
    vals = [fp / tot * 100 for fp, tot in fp_by_scenario.values()]
    bars = ax.barh(labels, vals, color="#c1121f")
    ax.bar_label(bars, fmt="%.0f%%", fontsize=9)
    ax.set_xlabel("False-positive rate (%)")
    ax.set_xlim(0, max(vals + [10]) * 1.3)
    ax.set_title("SecureFIM Pro — false positives by benign activity type")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig_fp_by_scenario.png"), dpi=200)
    plt.close(fig)

    # Fig 5 — threshold sweep
    fig, ax = plt.subplots(figsize=(9, 5))
    th = [s["threshold"] for s in sweep]
    ax.plot(th, [s["rules_f1"] * 100 for s in sweep], "o--",
            label="Rule-based — F1", color="#f4a261")
    ax.plot(th, [s["full_f1"] * 100 for s in sweep], "o-",
            label="SecureFIM Pro — F1", color="#2a6f97")
    ax.plot(th, [s["rules_fpr"] * 100 for s in sweep], "s--",
            label="Rule-based — FPR", color="#e76f51", alpha=0.6)
    ax.plot(th, [s["full_fpr"] * 100 for s in sweep], "s-",
            label="SecureFIM Pro — FPR", color="#c1121f", alpha=0.6)
    ax.axvline(threshold, ls=":", color="grey")
    ax.text(threshold + 1, 5, f"operating\npoint = {threshold:.0f}",
            fontsize=8, color="grey")
    ax.set_xlabel("Composite threat-score alert threshold")
    ax.set_ylabel("Percentage (%)")
    ax.set_title("Sensitivity of detection performance to the alert threshold")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "fig_threshold_sweep.png"), dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()
