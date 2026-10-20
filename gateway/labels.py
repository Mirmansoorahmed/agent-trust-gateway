"""Session data-flow labels. Labels are assigned by the gateway, not the server."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionState:
    saw_untrusted: bool = False
    holds_sensitive: bool = False
    sensitive_servers: set[str] = field(default_factory=set)

    def as_input(self, approvals_last_minute: int) -> dict:
        return {
            "saw_untrusted": self.saw_untrusted,
            "holds_sensitive": self.holds_sensitive,
            "sensitive_servers": sorted(self.sensitive_servers),
            "approvals_last_minute": approvals_last_minute,
        }

    def observe_result(self, *, server_id: str, labels: list[str], output_flags: list[str]) -> None:
        if "untrusted" in labels or output_flags:
            self.saw_untrusted = True
        if "sensitive" in labels:
            self.holds_sensitive = True
            self.sensitive_servers.add(server_id)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def get(self, session_id: str) -> SessionState:
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionState()
            self._sessions[session_id] = state
        return state

    def reset(self) -> None:
        self._sessions.clear()
