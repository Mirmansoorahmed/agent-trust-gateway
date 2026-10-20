"""Gateway configuration. Environment variables override the YAML file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ServerConfig:
    id: str
    url: str
    allowlisted: bool
    tool_labels: dict[str, list[str]]
    tool_scopes: dict[str, str]


@dataclass
class AgentConfig:
    id: str
    allowed_tools: list[str]


@dataclass
class Settings:
    gateway_audience: str = "agent-trust-gateway"
    max_token_ttl_seconds: int = 600
    downstream_ttl_seconds: int = 60
    oidc_issuer: str = "http://lab-issuer.local"
    oidc_jwks_url: str | None = None
    opa_url: str = "http://127.0.0.1:8181"
    resource_server_url: str = "http://127.0.0.1:8080/mcp"
    auth_issuer_url: str = "http://lab-issuer.local"
    manifest_path: Path | None = None
    approval_path: Path | None = None
    span_path: Path | None = None
    otlp_endpoint: str | None = None
    approver_token: str = "lab-approver"
    approval_rate_limit: int = 8
    recipient_allowlist: list[str] = field(default_factory=list)
    servers: list[ServerConfig] = field(default_factory=list)
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    auto_pin_allowlisted: bool = True

    def server(self, server_id: str) -> ServerConfig | None:
        return next((item for item in self.servers if item.id == server_id), None)

    def agent(self, agent_id: str) -> AgentConfig | None:
        return self.agents.get(agent_id)


def _servers(raw: list[dict]) -> list[ServerConfig]:
    servers = []
    for item in raw:
        servers.append(
            ServerConfig(
                id=item["id"],
                url=item["url"],
                allowlisted=bool(item.get("allowlisted", False)),
                tool_labels=item.get("tool_labels", {}),
                tool_scopes=item.get("tool_scopes", {}),
            )
        )
    return servers


def _agents(raw: dict) -> dict[str, AgentConfig]:
    return {
        agent_id: AgentConfig(id=agent_id, allowed_tools=list(spec.get("allowed_tools", [])))
        for agent_id, spec in raw.items()
    }


def load_settings(path: Path | None = None) -> Settings:
    data: dict = {}
    config_path = path or Path(os.environ.get("ATG_CONFIG", "config/gateway.yaml"))
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text()) or {}
    settings = Settings(
        gateway_audience=os.environ.get("ATG_AUDIENCE", data.get("gateway_audience", "agent-trust-gateway")),
        max_token_ttl_seconds=int(os.environ.get("ATG_MAX_TTL", data.get("max_token_ttl_seconds", 600))),
        downstream_ttl_seconds=int(os.environ.get("ATG_DOWNSTREAM_TTL", data.get("downstream_ttl_seconds", 60))),
        oidc_issuer=os.environ.get("ATG_OIDC_ISSUER", data.get("oidc_issuer", "http://lab-issuer.local")),
        oidc_jwks_url=os.environ.get("ATG_OIDC_JWKS_URL") or data.get("oidc_jwks_url"),
        opa_url=os.environ.get("ATG_OPA_URL", data.get("opa_url", "http://127.0.0.1:8181")),
        resource_server_url=os.environ.get(
            "ATG_RESOURCE_URL", data.get("resource_server_url", "http://127.0.0.1:8080/mcp")
        ),
        auth_issuer_url=os.environ.get("ATG_AUTH_ISSUER_URL", data.get("auth_issuer_url", "http://lab-issuer.local")),
        approver_token=os.environ.get("ATG_APPROVER_TOKEN", data.get("approver_token", "lab-approver")),
        approval_rate_limit=int(os.environ.get("ATG_APPROVAL_RATE_LIMIT", data.get("approval_rate_limit", 8))),
        recipient_allowlist=list(data.get("recipient_allowlist", [])),
        servers=_servers(data.get("servers", [])),
        agents=_agents(data.get("agents", {})),
        otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or data.get("otlp_endpoint"),
    )
    if os.environ.get("ATG_MANIFEST_PATH"):
        settings.manifest_path = Path(os.environ["ATG_MANIFEST_PATH"])
    elif data.get("manifest_path"):
        settings.manifest_path = Path(data["manifest_path"])
    if os.environ.get("ATG_APPROVAL_PATH"):
        settings.approval_path = Path(os.environ["ATG_APPROVAL_PATH"])
    elif data.get("approval_path"):
        settings.approval_path = Path(data["approval_path"])
    if os.environ.get("ATG_SPAN_PATH"):
        settings.span_path = Path(os.environ["ATG_SPAN_PATH"])
    elif data.get("span_path"):
        settings.span_path = Path(data["span_path"])
    return settings
