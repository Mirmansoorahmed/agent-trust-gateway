"""Start OPA, the synthetic MCP servers and the gateway on localhost."""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import uvicorn
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from gateway.app import create_app
from gateway.config import load_settings
from gateway.keys import SigningKey
from gateway.tokens import AGENT_ISSUER, DownstreamMinter, LabIssuer

ROOT = Path(__file__).resolve().parents[1]
PORTS = {
    "mail": 18101,
    "repo": 18102,
    "web": 18103,
    "poison": 18111,
    "rug": 18112,
    "shadow": 18113,
    "injection": 18114,
    "tokenreplay": 18115,
}
GATEWAY_PORT = 18200
OPA_PORT = 18181


def _wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=0.5)
            if response.status_code < 500:
                return
            last = f"status {response.status_code}"
        except httpx.HTTPError as exc:
            last = str(exc)
        time.sleep(0.15)
    raise TimeoutError(f"timed out waiting for {url}: {last}")


def _port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


@dataclass
class Running:
    server: uvicorn.Server
    thread: threading.Thread


def _serve(app, port: int) -> Running:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name=f"atg-{port}")
    thread.start()
    return Running(server, thread)


@dataclass
class Lab:
    root: Path = ROOT
    ports: dict[str, int] = field(default_factory=lambda: dict(PORTS))
    gateway_port: int = GATEWAY_PORT
    opa_port: int = OPA_PORT
    work: Path | None = None
    processes: list[subprocess.Popen] = field(default_factory=list)
    running: list[Running] = field(default_factory=list)
    issuer: LabIssuer | None = None
    gateway_minter: DownstreamMinter | None = None

    def start(self) -> None:
        for port in [*self.ports.values(), self.gateway_port, self.opa_port]:
            if not _port_free(port):
                raise RuntimeError(f"port {port} is already in use")
        self.work = self.root / "data" / "lab"
        self.work.mkdir(parents=True, exist_ok=True)
        lab_key = SigningKey.generate("lab-issuer")
        gateway_key = SigningKey.generate("gateway-1")
        (self.work / "lab_public.pem").write_bytes(lab_key.public_pem())
        (self.work / "gateway_public.pem").write_bytes(gateway_key.public_pem())
        self.issuer = LabIssuer(lab_key)
        self.gateway_minter = DownstreamMinter(gateway_key, ttl_seconds=60)

        opa = subprocess.Popen(
            [
                "opa",
                "run",
                "--server",
                "--addr",
                f"127.0.0.1:{self.opa_port}",
                str(self.root / "policies"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.processes.append(opa)
        _wait_http(f"http://127.0.0.1:{self.opa_port}/health")

        from gateway.verifiers import ServerTokenVerifier
        from servers.run import SERVERS

        verifier_kwargs = {
            "gateway_public_key": gateway_key.public_key,
            "allow_direct": True,
            "direct_public_key": lab_key.public_key,
        }
        for name, factory in SERVERS.items():
            verifier = ServerTokenVerifier(server_id=name, **verifier_kwargs)
            self.running.append(_serve(factory(verifier=verifier), self.ports[name]))
        for name, port in self.ports.items():
            _wait_http(f"http://127.0.0.1:{port}/health")

        settings = load_settings(self.root / "config" / "gateway.yaml")
        settings.oidc_issuer = AGENT_ISSUER
        settings.auth_issuer_url = "http://lab-issuer.local"
        settings.opa_url = f"http://127.0.0.1:{self.opa_port}"
        settings.resource_server_url = f"http://127.0.0.1:{self.gateway_port}/mcp"
        settings.otlp_endpoint = None
        settings.manifest_path = self.work / "manifests.json"
        settings.approval_path = self.work / "approvals.json"
        settings.span_path = self.work / "spans.jsonl"
        for server in settings.servers:
            server.url = f"http://127.0.0.1:{self.ports[server.id]}/mcp"
        app = create_app(
            settings,
            agent_public_keys=[lab_key.public_key],
            minter=self.gateway_minter,
        )
        self.running.append(_serve(app, self.gateway_port))
        _wait_http(f"http://127.0.0.1:{self.gateway_port}/health")
        self._settings = settings

    def stop(self) -> None:
        for running in self.running:
            running.server.should_exit = True
        for running in self.running:
            running.thread.join(timeout=5)
        for proc in self.processes:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.running.clear()
        self.processes.clear()

    def agent_token(self, agent_id: str, scopes: list[str], **kwargs) -> str:
        assert self.issuer is not None
        return self.issuer.agent_token(agent_id=agent_id, scopes=scopes, **kwargs)

    def direct_token(self, agent_id: str, server_id: str, scopes: list[str]) -> str:
        assert self.issuer is not None
        return self.issuer.direct_token(agent_id=agent_id, server_id=server_id, scopes=scopes)

    def effects(self, server_id: str) -> list[dict]:
        response = httpx.get(f"http://127.0.0.1:{self.ports[server_id]}/admin/effects", timeout=5)
        response.raise_for_status()
        return response.json()["events"]

    def reset_effects(self) -> None:
        for port in self.ports.values():
            httpx.post(f"http://127.0.0.1:{port}/admin/reset", timeout=5)

    def flip(self, server_id: str, mode: str = "description") -> dict:
        response = httpx.post(
            f"http://127.0.0.1:{self.ports[server_id]}/admin/flip",
            params={"mode": mode},
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    def reset_gateway(self) -> None:
        httpx.post(
            f"http://127.0.0.1:{self.gateway_port}/admin/reset",
            headers={"X-Approver-Token": "lab-approver"},
            timeout=5,
        ).raise_for_status()


async def mcp_call(url: str, token: str, tool: str, arguments: dict, session: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    if session:
        headers["X-ATG-Session"] = session
    http = httpx2_client(headers)
    try:
        async with Client(streamable_http_client(url, http_client=http), mode="legacy") as client:
            if tool == "tools/list":
                result = await client.list_tools()
                return {"tools": [item.name for item in result.tools]}
            result = await client.call_tool(tool, arguments)
            text = result.content[0].text if result.content else ""
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text, "is_error": result.is_error}
    finally:
        await http.aclose()


def httpx2_client(headers: dict):
    import httpx2

    return httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0))


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())
