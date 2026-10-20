"""PNG charts drawn only from the summary produced by this run."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

CONDITIONS = ("a", "b", "c", "d")
CONDITION_LABELS = {
    "a": "a no gateway",
    "b": "b scanners",
    "c": "c gateway",
    "d": "d gateway+scan",
}


def _grouped(path: Path, scenarios: list[str], series: dict[str, list[float]], title: str, ylabel: str) -> None:
    if not scenarios:
        return
    fig, ax = plt.subplots(figsize=(12, 5.2))
    width = 0.18
    indexes = list(range(len(scenarios)))
    for offset, condition in enumerate(CONDITIONS):
        values = series.get(condition) or [0] * len(scenarios)
        positions = [index + (offset - 1.5) * width for index in indexes]
        ax.bar(positions, values, width=width, label=CONDITION_LABELS[condition])
    ax.set_xticks(indexes)
    ax.set_xticklabels(scenarios, rotation=55, ha="right", fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(frameon=False, ncol=4, fontsize=8)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)


def write_charts(summary: dict, directory: Path) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    attacks = summary.get("attacks") or {}
    names = list(attacks)
    block = {condition: [] for condition in CONDITIONS}
    asr = {condition: [] for condition in CONDITIONS}
    for name in names:
        for condition in CONDITIONS:
            cell = attacks[name].get(condition) or {}
            block[condition].append(cell.get("block_rate") or 0)
            asr[condition].append(cell.get("asr") or 0)
    block_path = directory / "block_rate.png"
    asr_path = directory / "asr.png"
    _grouped(block_path, names, block, "Attack block rate by scenario and condition", "block rate")
    _grouped(asr_path, names, asr, "Attack success rate by scenario and condition", "attack success rate")

    latency = summary.get("latency_ms") or {}
    fig, ax = plt.subplots(figsize=(7, 4))
    labels = []
    p50 = []
    p95 = []
    for condition in ("c", "d"):
        cell = latency.get(condition) or {}
        if cell.get("n"):
            labels.append(CONDITION_LABELS[condition])
            p50.append(cell.get("p50") or 0)
            p95.append(cell.get("p95") or 0)
    if labels:
        positions = list(range(len(labels)))
        ax.bar([p - 0.15 for p in positions], p50, width=0.3, label="p50")
        ax.bar([p + 0.15 for p in positions], p95, width=0.3, label="p95")
        ax.set_xticks(positions)
        ax.set_xticklabels(labels)
    ax.set_ylabel("gateway overhead (ms)")
    ax.set_title("Added latency, model time excluded")
    ax.legend(frameon=False)
    fig.tight_layout()
    latency_path = directory / "latency.png"
    fig.savefig(latency_path, dpi=140)
    plt.close(fig)

    flagged = summary.get("scanner", {}).get("flagged_tools") or []
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.axis("off")
    lines = ["Cisco YARA flags (offline static scan)"]
    if not flagged:
        lines.append(summary.get("scanner", {}).get("cisco_yara", {}).get("reason") or "no tools flagged")
    else:
        lines.extend(flagged)
    ax.text(0.02, 0.98, "\n".join(lines), va="top", family="monospace", fontsize=9)
    fig.tight_layout()
    scanner_path = directory / "scanners.png"
    fig.savefig(scanner_path, dpi=140)
    plt.close(fig)
    return [str(block_path), str(asr_path), str(latency_path), str(scanner_path)]
