"""Fill docs/RESULTS.md and the README results block from summary.json.

Every number in the generated sections is read from the results file.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "eval" / "results" / "summary.json"
README = ROOT / "README.md"
RESULTS = ROOT / "docs" / "RESULTS.md"
START = "<!-- RESULTS:START -->"
END = "<!-- RESULTS:END -->"


def _pct(rate: float | None) -> str:
    if rate is None:
        return "—"
    return f"{rate * 100:.1f}%"


def _ci(interval) -> str:
    if not interval or interval[0] is None:
        return "—"
    return f"[{interval[0] * 100:.1f}%, {interval[1] * 100:.1f}%]"


def _ms(value) -> str:
    if value is None:
        return "—"
    return f"{value:.1f}"


def results_markdown(summary: dict) -> str:
    lines = [
        "# Evaluation results",
        "",
        f"Generated from `eval/results/summary.json` at {summary['generated_at']}.",
        f"Git SHA recorded at the start of the run: `{summary['git_sha']}`.",
        f"Agent: **scripted** ({summary['reps']} repetitions, bootstrap seed {summary['seed']}).",
        summary["agent_note"],
        "",
        "Conditions: (a) no gateway, (b) Cisco YARA then direct, (c) gateway, (d) YARA then gateway.",
        "Attack success means the attacker goal showed up in the server's effect log.",
        "A deny or an unapproved hold counts as a block. Approval was not granted during these runs.",
        "",
        "## Attack block rate",
        "",
        "| Scenario | Threat | a block | b block | c block | d block | a ASR | c ASR |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, cell in summary["attacks"].items():
        lines.append(
            "| {name} | {threat} | {a} | {b} | {c} | {d} | {asr_a} | {asr_c} |".format(
                name=name,
                threat=cell.get("threat", ""),
                a=_pct(cell["a"]["block_rate"]),
                b=_pct(cell["b"]["block_rate"]),
                c=_pct(cell["c"]["block_rate"]),
                d=_pct(cell["d"]["block_rate"]),
                asr_a=_pct(cell["a"]["asr"]),
                asr_c=_pct(cell["c"]["asr"]),
            )
        )
    lines += [
        "",
        "95% bootstrap intervals are in `summary.json` under each scenario. "
        "A control that blocked every repetition has interval [100%, 100%]. "
        "That is the interval of a constant, not a claim of precision beyond the sample.",
        "",
        "## Benign suite",
        "",
        f"{summary['benign_tasks_per_rep']} tasks per repetition. "
        "False block = deny, hold, scanner pre-block, or rejection on a task that should be allowed.",
        "",
        "| Condition | Success | False-block rate | 95% CI (false block) |",
        "|---|---:|---:|---:|",
    ]
    for condition in ("a", "b", "c", "d"):
        cell = summary["benign"][condition]
        lines.append(
            f"| {condition} | {_pct(cell['success_rate']['rate'])} | "
            f"{_pct(cell['false_block_rate']['rate'])} | {_ci(cell['false_block_rate']['ci95'])} |"
        )
    latency = summary["latency_ms"]
    drift = summary["drift_detection_ms"]
    lines += [
        "",
        "## Latency and drift",
        "",
        "Overhead is gateway time minus the upstream tool-call time. Model time is not included, "
        "because the scripted agent does not call a model.",
        "",
        "| Condition | Overhead n | p50 ms | p95 ms | Drift detection p50 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    for condition in ("a", "b", "c", "d"):
        lat = latency[condition]
        drift_cell = drift[condition]
        lines.append(
            f"| {condition} | {lat['n']} | {_ms(lat['p50'])} | {_ms(lat['p95'])} | {_ms(drift_cell['p50'])} |"
        )
    lines += [
        "",
        "Drift time is measured on `t2_description` from the admin flip to the gateway's decision. "
        "Conditions (a) and (b) do not detect drift.",
        "",
        "## Token matrix",
        "",
        "| Case | Pass | Detail |",
        "|---|---|---|",
    ]
    for row in summary["token_matrix"]:
        detail = str(row.get("detail", "")).replace("|", "/").replace("\n", " ")
        if len(detail) > 160:
            detail = detail[:157] + "..."
        lines.append(f"| {row['id']} | {'pass' if row['pass'] else 'fail'} | {detail} |")
    scanner = summary["scanner"]
    lines += [
        "",
        "## Scanners",
        "",
        f"Cisco YARA available: {scanner['cisco_yara']['available']}.",
        f"Flagged tools: {', '.join(scanner['flagged_tools']) or 'none'}.",
        f"Snyk: {scanner['snyk']['status']}. {scanner['snyk']['reason']}",
        "",
        "## Separately reported",
        "",
        "Expected holds (gateway, legitimate send after a benign untrusted page): "
        f"{summary['expected_holds']['held']}/{summary['expected_holds']['n']}. "
        f"{summary['expected_holds']['note']}",
        "",
        "Residual silent BCC (clean description, server allowlisted on purpose): "
        f"attacker goal reached {summary['residual_silent_bcc']['attacker_goal_reached']}/"
        f"{summary['residual_silent_bcc']['n']}. {summary['residual_silent_bcc']['note']}",
        "",
        "## Real model",
        "",
        summary.get("real_llm", {}).get("note", ""),
        "",
        _llm_section(),
        "",
        "Charts: `eval/results/charts/block_rate.png`, `eval/results/charts/asr.png`, "
        "`eval/results/charts/latency.png`, `eval/results/charts/scanners.png`.",
        "Row-level data: `eval/results/trials.csv`.",
        "",
    ]
    return "\n".join(lines)


def _llm_section() -> str:
    path = ROOT / "eval" / "results" / "llm_sample.json"
    if not path.exists():
        return "No `eval/results/llm_sample.json` was written in this run."
    sample = json.loads(path.read_text())
    lines = [f"File status: {sample.get('status')}. {sample.get('reason', '')}".rstrip()]
    counted = sample.get("summary")
    if counted:
        lines.append(
            "The local model called the prompted tool in "
            f"{counted['model_called_expected']} of {counted['of']} prompts. "
            f"Model or transport errors: {counted['errors']}."
        )
    by_kind: dict[str, list[str]] = {}
    for trial in sample.get("trials") or []:
        by_kind.setdefault(str(trial.get("kind")), []).append(str(trial.get("gateway_decision")))
    for kind, decisions in by_kind.items():
        lines.append(f"{kind}: gateway decisions {', '.join(decisions)}.")
    lines.append("These counts are not included in the scripted rates above.")
    return "\n".join(lines)


def readme_block(summary: dict) -> str:
    benign_c = summary["benign"]["c"]
    lat = summary["latency_ms"]["c"]
    lines = [
        START,
        "",
        f"Scripted agent, {summary['reps']} repetitions, run at {summary['generated_at']} "
        f"(git `{summary['git_sha']}`). These numbers are not from a live model.",
        "",
        "| | No gateway (a) | Gateway (c) |",
        "|---|---:|---:|",
    ]
    # Headline rows: mean block across scenarios is misleading. Show the rows a hiring manager needs.
    highlights = [
        "t1_export_contacts",
        "t1_export_hidden",
        "t1_export_zwsp",
        "t2_description",
        "t3_explicit_bcc",
        "t3_cross_server",
        "t5_missing_scope",
        "t6_injection_colleague",
    ]
    for name in highlights:
        cell = summary["attacks"][name]
        lines.append(
            f"| Block {name} | {_pct(cell['a']['block_rate'])} | {_pct(cell['c']['block_rate'])} |"
        )
    lines += [
        f"| Benign success | {_pct(summary['benign']['a']['success_rate']['rate'])} | {_pct(benign_c['success_rate']['rate'])} |",
        f"| Benign false-block | {_pct(summary['benign']['a']['false_block_rate']['rate'])} | {_pct(benign_c['false_block_rate']['rate'])} |",
        f"| Gateway overhead p50 / p95 | — | {_ms(lat['p50'])} ms / {_ms(lat['p95'])} ms |",
        "",
        "Full table, intervals, scanner notes and the token matrix: [docs/RESULTS.md](docs/RESULTS.md).",
        "",
        END,
        "",
    ]
    return "\n".join(lines)


def render(summary_path: Path = SUMMARY) -> None:
    summary = json.loads(summary_path.read_text())
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(results_markdown(summary))
    readme = README.read_text()
    block = readme_block(summary)
    if START not in readme or END not in readme:
        raise SystemExit("README.md is missing RESULTS markers")
    prefix, rest = readme.split(START, 1)
    _old, suffix = rest.split(END, 1)
    README.write_text(prefix + block + suffix.lstrip("\n"))


if __name__ == "__main__":
    render()
