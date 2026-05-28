"""Generate markdown reports and matplotlib charts from evaluation results."""
from __future__ import annotations
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

if TYPE_CHECKING:
    from .runner import Result

CATEGORIES = ["sql_injection", "xss", "path_traversal", "cmd_injection",
              "file_upload", "rate_limit"]


def _compute_metrics(results: "list[Result]") -> dict:
    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    )
    # Benign-categorized payloads contribute FP/TN to the category they were
    # supposed to be testing... but our payload schema uses `category: benign`.
    # So benign FP/TN belongs to a virtual "benign" category for FPR computation.
    for r in results:
        by_cat[r.category][r.outcome] += 1

    metrics = {}
    for cat, counts in by_cat.items():
        tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tpr
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        metrics[cat] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                        "TPR": tpr, "FPR": fpr, "F1": f1}
    return metrics


def _plot_overall(metrics: dict, figures_dir: Path, label: str) -> None:
    cats = [c for c in CATEGORIES if c in metrics]
    if not cats:
        return
    tprs = [metrics[c]["TPR"] * 100 for c in cats]
    fprs = [metrics[c].get("FPR", 0) * 100 for c in cats]

    x = list(range(len(cats)))
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([i - 0.2 for i in x], tprs, 0.4, label="TPR %", color="#2196F3")
    ax.bar([i + 0.2 for i in x], fprs, 0.4, label="FPR %", color="#FF5722")
    ax.set_xticks(x)
    ax.set_xticklabels(cats, rotation=30, ha="right")
    ax.set_ylabel("Percentage")
    ax.set_title(f"WAF Detection Rates - {label}")
    ax.legend()
    ax.set_ylim(0, 105)
    fig.tight_layout()
    fig.savefig(figures_dir / f"overall-{label}.png", dpi=150)
    plt.close(fig)


def _plot_confusion(metrics: dict, figures_dir: Path, label: str) -> None:
    cats = [c for c in CATEGORIES if c in metrics]
    if not cats:
        return
    matrix = [[metrics[c]["TP"], metrics[c]["FN"], metrics[c]["FP"], metrics[c]["TN"]]
              for c in cats]

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")
    ax.set_xticks([0, 1, 2, 3])
    ax.set_xticklabels(["TP", "FN", "FP", "TN"])
    ax.set_yticks(range(len(cats)))
    ax.set_yticklabels(cats)
    for i in range(len(cats)):
        for j in range(4):
            ax.text(j, i, str(matrix[i][j]), ha="center", va="center")
    ax.set_title(f"Confusion Matrix - {label}")
    fig.colorbar(im)
    fig.tight_layout()
    fig.savefig(figures_dir / f"confusion-{label}.png", dpi=150)
    plt.close(fig)


def generate(results: "list[Result]", output_dir: str, label: str = "baseline") -> str:
    out = Path(output_dir)
    figures_dir = out / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    metrics = _compute_metrics(results)
    _plot_overall(metrics, figures_dir, label)
    _plot_confusion(metrics, figures_dir, label)

    today = date.today().isoformat()
    md_path = out / f"{label}-{today}.md"

    lines = [f"# WAF Evaluation Report - {label} - {today}\n\n## Summary\n\n"]
    lines.append("| Category | TP | FN | FP | TN | TPR | FPR | F1 |\n")
    lines.append("|----------|----|----|----|----|-----|-----|----|\n")
    for cat in CATEGORIES:
        if cat not in metrics:
            continue
        m = metrics[cat]
        lines.append(
            f"| {cat} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} "
            f"| {m['TPR']:.1%} | {m['FPR']:.1%} | {m['F1']:.3f} |\n"
        )
    # Include benign separately if present
    if "benign" in metrics:
        m = metrics["benign"]
        lines.append(
            f"| benign | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} "
            f"| {m['TPR']:.1%} | {m['FPR']:.1%} | {m['F1']:.3f} |\n"
        )

    lines.append("\n## Failed Payloads (FN - bypassed WAF)\n\n")
    fn_results = [r for r in results if r.outcome == "FN"]
    if not fn_results:
        lines.append("_(none)_\n")
    for r in fn_results:
        lines.append(f"- `{r.payload_id}` ({r.category}, status={r.status_code})\n")

    lines.append("\n## False Positives (FP - benign blocked)\n\n")
    fp_results = [r for r in results if r.outcome == "FP"]
    if not fp_results:
        lines.append("_(none)_\n")
    for r in fp_results:
        lines.append(f"- `{r.payload_id}` ({r.category}, status={r.status_code})\n")

    lines.append("\n## Charts\n\n")
    lines.append(f"![Overall](figures/overall-{label}.png)\n\n")
    lines.append(f"![Confusion Matrix](figures/confusion-{label}.png)\n\n")

    md_path.write_text("".join(lines), encoding="utf-8")
    return str(md_path)


def generate_comparison(
    baseline_results: "list[Result]",
    hardened_results: "list[Result]",
    output_dir: str,
) -> str:
    out = Path(output_dir)
    figures_dir = out / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    m_base = _compute_metrics(baseline_results)
    m_hard = _compute_metrics(hardened_results)

    cats = [c for c in CATEGORIES if c in m_base and c in m_hard]
    if cats:
        x = list(range(len(cats)))
        fig, ax = plt.subplots(figsize=(12, 5))
        w = 0.2
        ax.bar([i - 1.5 * w for i in x], [m_base[c]["TPR"] * 100 for c in cats],
               w, label="Baseline TPR", color="#90CAF9")
        ax.bar([i - 0.5 * w for i in x], [m_hard[c]["TPR"] * 100 for c in cats],
               w, label="Hardened TPR", color="#1565C0")
        ax.bar([i + 0.5 * w for i in x], [m_base[c]["FPR"] * 100 for c in cats],
               w, label="Baseline FPR", color="#FFAB91")
        ax.bar([i + 1.5 * w for i in x], [m_hard[c]["FPR"] * 100 for c in cats],
               w, label="Hardened FPR", color="#D84315")
        ax.set_xticks(x)
        ax.set_xticklabels(cats, rotation=30, ha="right")
        ax.set_ylabel("Percentage")
        ax.set_title("WAF Evaluation - Baseline vs Hardened")
        ax.legend()
        fig.tight_layout()
        fig.savefig(figures_dir / "overall-comparison.png", dpi=150)
        plt.close(fig)

    md_path = out / "comparison.md"
    lines = ["# WAF Evaluation - Baseline vs Hardened Comparison\n\n"]
    lines.append("| Category | Baseline TPR | Hardened TPR | ΔTPR | Baseline FPR | Hardened FPR | ΔFPR |\n")
    lines.append("|----------|-------------|-------------|------|-------------|-------------|------|\n")
    for cat in cats:
        b, h = m_base[cat], m_hard[cat]
        lines.append(
            f"| {cat} | {b['TPR']:.1%} | {h['TPR']:.1%} | {(h['TPR'] - b['TPR']) * 100:+.1f}pp "
            f"| {b['FPR']:.1%} | {h['FPR']:.1%} | {(h['FPR'] - b['FPR']) * 100:+.1f}pp |\n"
        )
    lines.append("\n![Comparison](figures/overall-comparison.png)\n")
    md_path.write_text("".join(lines), encoding="utf-8")
    return str(md_path)
