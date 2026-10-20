"""Human-approval queue. Grants are one-shot and bound to the exact arguments."""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Approval:
    id: str
    created_at: float
    agent_id: str
    server_id: str
    tool: str
    arguments: dict
    reason: str
    status: str = "pending"  # pending | approved | denied
    decided_at: float | None = None
    decided_by: str | None = None
    decision_note: str = ""
    consumed: bool = False


def _canonical_args(arguments: dict) -> str:
    return json.dumps(arguments, sort_keys=True, default=str)


@dataclass
class ApprovalQueue:
    path: Path | None = None
    rate_window_seconds: float = 60.0
    items: dict[str, Approval] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text())
        self.items = {item["id"]: Approval(**item) for item in raw}

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(item) for item in self.items.values()]
        self.path.write_text(json.dumps(payload, indent=2))

    def recent_count(self, agent_id: str, now: float | None = None) -> int:
        current = time.time() if now is None else now
        with self._lock:
            return sum(
                1
                for item in self.items.values()
                if item.agent_id == agent_id and current - item.created_at <= self.rate_window_seconds
            )

    def create(self, *, agent_id: str, server_id: str, tool: str, arguments: dict, reason: str) -> Approval:
        approval = Approval(
            id=f"apr_{uuid.uuid4().hex[:12]}",
            created_at=time.time(),
            agent_id=agent_id,
            server_id=server_id,
            tool=tool,
            arguments=arguments,
            reason=reason,
        )
        with self._lock:
            self.items[approval.id] = approval
            self.save()
        return approval

    def list(self, status: str | None = None) -> list[Approval]:
        with self._lock:
            items = list(self.items.values())
        if status:
            items = [item for item in items if item.status == status]
        return sorted(items, key=lambda item: item.created_at)

    def decide(self, approval_id: str, decision: str, *, actor: str, note: str = "") -> Approval:
        if decision not in {"approved", "denied"}:
            raise ValueError("decision must be approved or denied")
        with self._lock:
            item = self.items.get(approval_id)
            if item is None:
                raise KeyError(approval_id)
            if item.status != "pending":
                raise ValueError(f"approval is already {item.status}")
            item.status = decision
            item.decided_at = time.time()
            item.decided_by = actor
            item.decision_note = note
            self.save()
            return item

    def consume_grant(self, *, agent_id: str, tool: str, arguments: dict) -> Approval | None:
        wanted = _canonical_args(arguments)
        with self._lock:
            for item in self.items.values():
                if (
                    item.status == "approved"
                    and not item.consumed
                    and item.agent_id == agent_id
                    and item.tool == tool
                    and _canonical_args(item.arguments) == wanted
                ):
                    item.consumed = True
                    self.save()
                    return item
        return None

    def reset(self) -> None:
        with self._lock:
            self.items.clear()
            self.save()
