"""The policy enforcement path for one tools/list or tools/call."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from gateway.approvals import ApprovalQueue
from gateway.auth import AgentIdentity
from gateway.config import ServerConfig, Settings
from gateway.labels import SessionStore
from gateway.linter import lint_description, lint_output
from gateway.manifest import DriftCheck, ManifestStore
from gateway.policy import OpaClient, PolicyClient
from gateway.telemetry import Telemetry, mark_status
from gateway.tokens import DownstreamMinter
from gateway.upstream import UpstreamPool


@dataclass
class CallTrace:
    decision: str
    reason: str
    reasons: list[str] = field(default_factory=list)
    approval_reasons: list[str] = field(default_factory=list)
    approval_id: str | None = None
    server_id: str = ""
    tool: str = ""
    manifest_hash: str = ""
    drift: bool = False
    poison_flags: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    output_flags: list[str] = field(default_factory=list)
    text: str = ""
    upstream_ms: float = 0.0
    overhead_ms: float = 0.0
    token_observation: dict | None = None
    agent_token_sha256: str = ""


def split_tool(qualified: str) -> tuple[str, str]:
    server_id, separator, name = qualified.partition(".")
    if not separator or not name:
        raise ValueError("tool name must be server.tool")
    return server_id, name


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class GatewayService:
    def __init__(
        self,
        settings: Settings,
        *,
        minter: DownstreamMinter,
        policy: PolicyClient | None = None,
        pool: UpstreamPool | None = None,
        telemetry: Telemetry | None = None,
    ):
        self.settings = settings
        self.minter = minter
        self.policy = policy or OpaClient(settings.opa_url)
        self.pool = pool or UpstreamPool()
        self.manifests = ManifestStore(settings.manifest_path)
        self.manifests.load()
        self.approvals = ApprovalQueue(settings.approval_path)
        self.approvals.load()
        self.sessions = SessionStore()
        self.telemetry = telemetry or Telemetry(
            span_path=settings.span_path,
            otlp_endpoint=settings.otlp_endpoint,
        )

    async def aclose(self) -> None:
        await self.pool.aclose()
        close = getattr(self.policy, "aclose", None)
        if close:
            await close()
        self.telemetry.shutdown()

    async def list_tools(self, agent: AgentIdentity) -> list[dict]:
        listed: list[dict] = []
        for server in self.settings.servers:
            try:
                tools, check = await self._refresh(server, agent.agent_id)
            except Exception as exc:  # a dead upstream must not blank the whole catalogue
                listed.append(
                    {
                        "name": f"{server.id}.__unreachable",
                        "description": f"upstream {server.id} could not be listed: {exc.__class__.__name__}",
                        "input_schema": {"type": "object", "properties": {}},
                        "meta": {"atg.unreachable": True, "atg.server": server.id},
                    }
                )
                continue
            for tool in tools:
                flags = lint_description(tool["description"])
                listed.append(
                    {
                        "name": f"{server.id}.{tool['name']}",
                        "description": tool["description"],
                        "input_schema": tool["input_schema"],
                        "meta": {
                            "atg.server": server.id,
                            "atg.allowlisted": server.allowlisted,
                            "atg.drift": check.drift,
                            "atg.manifest_sha256": check.sha256,
                            "atg.poison_flags": flags,
                            "atg.labels": server.tool_labels.get(tool["name"], []),
                        },
                    }
                )
        return listed

    async def call_tool(
        self,
        agent: AgentIdentity,
        session_id: str,
        qualified: str,
        arguments: dict | None,
    ) -> CallTrace:
        started = time.perf_counter()
        arguments = arguments or {}
        trace = CallTrace(
            decision="deny",
            reason="denied by default",
            agent_token_sha256=_sha256(agent.token),
        )
        try:
            server_id, tool_name = split_tool(qualified)
        except ValueError:
            trace.reason = "tool name must be server.tool"
            trace.reasons = [trace.reason]
            self._span(trace, agent, session_id, started)
            return trace
        trace.server_id = server_id
        trace.tool = qualified
        server = self.settings.server(server_id)
        if server is None:
            trace.reason = "unknown server"
            trace.reasons = [trace.reason]
            self._span(trace, agent, session_id, started)
            return trace

        try:
            tools, check = await self._refresh(server, agent.agent_id)
        except Exception as exc:
            trace.reason = f"upstream list failed: {exc.__class__.__name__}"
            trace.reasons = [trace.reason]
            trace.overhead_ms = (time.perf_counter() - started) * 1000
            self._span(trace, agent, session_id, started)
            return trace

        trace.manifest_hash = check.sha256
        trace.drift = check.drift
        tool = next((item for item in tools if item["name"] == tool_name), None)
        if tool is None:
            trace.reason = "unknown tool"
            trace.reasons = [trace.reason]
            trace.upstream_ms = 0.0
            # The catalogue fetch is control-plane work, counted as overhead.
            trace.overhead_ms = (time.perf_counter() - started) * 1000
            self._span(trace, agent, session_id, started)
            return trace

        flags = lint_description(tool["description"])
        labels = list(server.tool_labels.get(tool_name, []))
        required_scope = server.tool_scopes.get(tool_name, "")
        trace.poison_flags = flags
        trace.labels = labels
        agent_cfg = self.settings.agent(agent.agent_id)
        allowed = agent_cfg.allowed_tools if agent_cfg else []
        session = self.sessions.get(session_id)
        payload = {
            "agent": {"id": agent.agent_id, "scopes": agent.scopes, "allowed_tools": allowed},
            "server": {"id": server.id, "allowlisted": server.allowlisted, "drift": check.drift},
            "tool": {
                "qualified_name": qualified,
                "name": tool_name,
                "server_id": server.id,
                "labels": labels,
                "poison_flags": flags,
                "required_scope": required_scope,
            },
            "args": arguments,
            "session": session.as_input(self.approvals.recent_count(agent.agent_id)),
            "policy": {
                "recipient_allowlist": self.settings.recipient_allowlist,
                "approval_rate_limit": self.settings.approval_rate_limit,
            },
        }
        verdict = await self.policy.decide(payload)
        trace.decision = verdict.get("decision", "deny")
        trace.reason = verdict.get("reason", "")
        trace.reasons = list(verdict.get("reasons") or [])
        trace.approval_reasons = list(verdict.get("approval_reasons") or [])

        if trace.decision == "needs_approval":
            grant = self.approvals.consume_grant(
                agent_id=agent.agent_id, tool=qualified, arguments=arguments
            )
            if grant is not None:
                trace.decision = "allow"
                trace.reason = f"human approved {grant.id}"
                trace.approval_id = grant.id
            else:
                approval = self.approvals.create(
                    agent_id=agent.agent_id,
                    server_id=server.id,
                    tool=qualified,
                    arguments=arguments,
                    reason=trace.reason,
                )
                trace.approval_id = approval.id
                trace.text = json.dumps(
                    {"atg_decision": "needs_approval", "approval_id": approval.id, "reason": trace.reason}
                )
                trace.overhead_ms = (time.perf_counter() - started) * 1000
                self._span(trace, agent, session_id, started)
                return trace

        if trace.decision != "allow":
            trace.text = json.dumps({"atg_decision": trace.decision, "reason": trace.reason})
            trace.overhead_ms = (time.perf_counter() - started) * 1000
            self._span(trace, agent, session_id, started)
            return trace

        downstream = self.minter.for_server(
            agent_id=agent.agent_id,
            server_id=server.id,
            scopes=[required_scope] if required_scope else [],
        )
        # The agent token and the downstream token are different strings.
        if downstream == agent.token:
            trace.decision = "deny"
            trace.reason = "refusing to forward the agent token"
            trace.reasons = [trace.reason]
            trace.text = json.dumps({"atg_decision": "deny", "reason": trace.reason})
            trace.overhead_ms = (time.perf_counter() - started) * 1000
            self._span(trace, agent, session_id, started)
            return trace

        call_started = time.perf_counter()
        try:
            text = await self.pool.call_tool(server.url, downstream, tool_name, arguments)
        except Exception as exc:
            trace.decision = "deny"
            trace.reason = f"upstream call failed: {exc.__class__.__name__}"
            trace.reasons = [trace.reason]
            trace.text = json.dumps({"atg_decision": "deny", "reason": trace.reason})
            trace.upstream_ms = (time.perf_counter() - call_started) * 1000
            trace.overhead_ms = max((time.perf_counter() - started) * 1000 - trace.upstream_ms, 0)
            self._span(trace, agent, session_id, started)
            return trace
        trace.upstream_ms = (time.perf_counter() - call_started) * 1000
        trace.text = text
        trace.output_flags = lint_output(text)
        trace.token_observation = _token_observation(text)
        session.observe_result(server_id=server.id, labels=labels, output_flags=trace.output_flags)
        trace.overhead_ms = max((time.perf_counter() - started) * 1000 - trace.upstream_ms, 0)
        self._span(trace, agent, session_id, started)
        return trace

    async def _refresh(self, server: ServerConfig, agent_id: str) -> tuple[list[dict], DriftCheck]:
        token = self.minter.for_server(agent_id=agent_id, server_id=server.id, scopes=["tools.list"])
        tools = await self.pool.list_tools(server.url, token)
        check = self.manifests.observe(
            server.id,
            tools,
            auto_pin=self.settings.auto_pin_allowlisted and server.allowlisted,
        )
        return tools, check

    def _span(self, trace: CallTrace, agent: AgentIdentity, session_id: str, started: float) -> None:
        attributes = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": trace.tool or "unknown",
            "gen_ai.tool.type": "function",
            "gen_ai.agent.name": agent.agent_id,
            "gen_ai.conversation.id": session_id,
            "atg.decision": trace.decision,
            "atg.reason": trace.reason,
            "atg.server": trace.server_id,
            "atg.manifest_sha256": trace.manifest_hash,
            "atg.drift": trace.drift,
            "atg.labels": trace.labels,
            "atg.poison_flags": trace.poison_flags,
            "atg.overhead_ms": round(trace.overhead_ms, 3),
            "atg.upstream_ms": round(trace.upstream_ms, 3),
            "atg.semconv": "gen-ai execute_tool development 2026-10-20",
        }
        with self.telemetry.decision_span(**attributes) as span:
            mark_status(span, trace.decision)
            if trace.approval_id:
                span.set_attribute("atg.approval_id", trace.approval_id)
            span.set_attribute("atg.elapsed_ms", round((time.perf_counter() - started) * 1000, 3))


def _token_observation(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    token = payload.get("token") if isinstance(payload, dict) else None
    return token if isinstance(token, dict) else None
