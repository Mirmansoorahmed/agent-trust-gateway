"""Baseline scanners.

Cisco mcp-scanner YARA mode is offline. Snyk Agent Scan is skipped unless
SNYK_TOKEN is set, because it would send tool metadata to Snyk.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def scanner_binary() -> str | None:
    override = os.environ.get("ATG_MCP_SCANNER")
    if override and Path(override).exists():
        return override
    found = shutil.which("mcp-scanner")
    if found:
        return found
    candidate = Path("/tmp/scanner-venv/bin/mcp-scanner")
    if candidate.exists():
        return str(candidate)
    return None


def yara_scan(tools: list[dict]) -> dict:
    binary = scanner_binary()
    if binary is None:
        return {"available": False, "reason": "mcp-scanner is not installed", "tools": []}
    payload = {
        "tools": [
            {
                "name": tool["name"],
                "description": tool.get("description") or "",
                "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
            }
            for tool in tools
        ]
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "tools.json"
        path.write_text(json.dumps(payload))
        completed = subprocess.run(
            [binary, "--analyzers", "yara", "--format", "raw", "static", "--tools", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    if completed.returncode != 0:
        return {
            "available": False,
            "reason": completed.stderr.strip()[:500] or f"exit {completed.returncode}",
            "tools": [],
        }
    report = json.loads(completed.stdout)
    parsed = []
    for item in report.get("scan_results") or []:
        finding = (item.get("findings") or {}).get("yara_analyzer") or {}
        parsed.append(
            {
                "name": item.get("tool_name"),
                "is_safe": bool(item.get("is_safe")),
                "severity": finding.get("severity"),
                "threats": finding.get("threat_names") or [],
            }
        )
    return {"available": True, "reason": "", "tools": parsed, "binary": binary}


def snyk_status() -> dict:
    if os.environ.get("SNYK_TOKEN"):
        return {
            "status": "not_run",
            "reason": "SNYK_TOKEN is set but this runner does not call Snyk. Remove the token to keep the lab offline.",
        }
    return {"status": "skipped", "reason": "SNYK_TOKEN is not set; Snyk Agent Scan would upload tool metadata."}
