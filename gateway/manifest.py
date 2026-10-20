"""SHA-256 pins of each server's tool list, and drift detection."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


def canonical_manifest(tools: list[dict]) -> str:
    items = []
    for tool in sorted(tools, key=lambda item: item["name"]):
        items.append(
            {
                "name": tool["name"],
                "description": tool.get("description") or "",
                "input_schema": tool.get("input_schema") or {},
            }
        )
    return json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_sha256(tools: list[dict]) -> str:
    return hashlib.sha256(canonical_manifest(tools).encode()).hexdigest()


@dataclass
class Pin:
    server_id: str
    sha256: str
    pinned_at: float
    tool_names: list[str]


@dataclass
class DriftCheck:
    server_id: str
    sha256: str
    drift: bool
    pinned: bool
    previous: str | None = None


@dataclass
class ManifestStore:
    path: Path | None = None
    pins: dict[str, Pin] = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text())
        self.pins = {
            server_id: Pin(
                server_id=server_id,
                sha256=item["sha256"],
                pinned_at=item["pinned_at"],
                tool_names=item.get("tool_names", []),
            )
            for server_id, item in raw.get("pins", {}).items()
        }

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pins": {
                server_id: {
                    "sha256": pin.sha256,
                    "pinned_at": pin.pinned_at,
                    "tool_names": pin.tool_names,
                }
                for server_id, pin in self.pins.items()
            }
        }
        self.path.write_text(json.dumps(payload, indent=2))

    def observe(self, server_id: str, tools: list[dict], *, auto_pin: bool) -> DriftCheck:
        digest = manifest_sha256(tools)
        names = sorted(tool["name"] for tool in tools)
        with self._lock:
            pin = self.pins.get(server_id)
            if pin is None:
                if auto_pin:
                    self.pins[server_id] = Pin(
                        server_id=server_id,
                        sha256=digest,
                        pinned_at=time.time(),
                        tool_names=names,
                    )
                    self.save()
                return DriftCheck(server_id=server_id, sha256=digest, drift=False, pinned=auto_pin)
            drift = pin.sha256 != digest
            if drift:
                self.alerts.append(
                    {
                        "server_id": server_id,
                        "at": time.time(),
                        "previous": pin.sha256,
                        "current": digest,
                        "kind": "manifest_drift",
                    }
                )
            return DriftCheck(
                server_id=server_id,
                sha256=digest,
                drift=drift,
                pinned=True,
                previous=pin.sha256,
            )

    def reset(self) -> None:
        with self._lock:
            self.pins.clear()
            self.alerts.clear()
            self.save()
