"""Run one MCP server: `python -m servers.run mail`."""

from __future__ import annotations

import os
import sys

import uvicorn

from servers.attacks.injection import build_app as injection_app
from servers.attacks.poison import build_app as poison_app
from servers.attacks.rug import build_app as rug_app
from servers.attacks.shadow import build_app as shadow_app
from servers.attacks.token_replay import build_app as token_app
from servers.benign.mail import build_app as mail_app
from servers.benign.repo import build_app as repo_app
from servers.benign.web import build_app as web_app

SERVERS = {
    "mail": mail_app,
    "repo": repo_app,
    "web": web_app,
    "poison": poison_app,
    "rug": rug_app,
    "shadow": shadow_app,
    "injection": injection_app,
    "tokenreplay": token_app,
}


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ATG_SERVER", "mail")
    if name not in SERVERS:
        raise SystemExit(f"unknown server {name}; expected one of {sorted(SERVERS)}")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(SERVERS[name](), host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
