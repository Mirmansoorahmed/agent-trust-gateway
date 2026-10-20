"""Approval queue CLI.

    python -m gateway.cli approvals list
    python -m gateway.cli approvals decide apr_xxx deny --note "not this recipient"
"""

from __future__ import annotations

import argparse
import json
import os

import httpx


def _client() -> tuple[str, dict]:
    base = os.environ.get("ATG_URL", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("ATG_APPROVER_TOKEN", "lab-approver")
    return base, {"X-Approver-Token": token}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="atg")
    sub = parser.add_subparsers(dest="group", required=True)
    approvals = sub.add_parser("approvals")
    commands = approvals.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    decide = commands.add_parser("decide")
    decide.add_argument("approval_id")
    decide.add_argument("decision", choices=["approve", "deny", "approved", "denied"])
    decide.add_argument("--note", default="")
    args = parser.parse_args(argv)
    base, headers = _client()
    if args.command == "list":
        response = httpx.get(f"{base}/api/approvals", headers=headers, timeout=10)
        response.raise_for_status()
        print(json.dumps(response.json(), indent=2))
        return
    decision = {"approve": "approved", "deny": "denied"}.get(args.decision, args.decision)
    response = httpx.post(
        f"{base}/api/approvals/{args.approval_id}",
        headers={**headers, "Content-Type": "application/json"},
        json={"decision": decision, "note": args.note, "actor": "cli"},
        timeout=10,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
