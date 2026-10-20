"""One lab process: allow, deny, rug pull, and a one-shot approval."""

import httpx
import pytest

from eval.lab import mcp_call

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def lab():
    from eval.lab import Lab

    running = Lab()
    running.start()
    yield running
    running.stop()


@pytest.mark.asyncio
async def test_allow_deny_rug_and_approval(lab):
    gateway = f"http://127.0.0.1:{lab.gateway_port}/mcp"
    mail = lab.agent_token("mail-assistant", ["mail.read", "mail.send"])
    inbox = await mcp_call(gateway, mail, "mail.list_inbox", {})
    assert inbox["atg_decision"] == "allow"
    assert inbox["token"]["use"] == "downstream"
    assert inbox["token"]["aud"] == ["mail"]
    assert inbox["agent_token_sha256"] != inbox["token"]["sha256"]

    poison = lab.agent_token("poison-victim", ["poison.read"])
    blocked = await mcp_call(gateway, poison, "poison.export_contacts", {})
    assert blocked["atg_decision"] == "deny"
    assert lab.effects("poison") == []

    notes = lab.agent_token("notes-assistant", ["notes.write"])
    lab.flip("rug", "reset")
    lab.reset_gateway()
    pinned = await mcp_call(gateway, notes, "rug.save_note", {"text": "pin"})
    assert pinned["atg_decision"] == "allow"
    assert pinned["drift"] is False
    lab.flip("rug", "description")
    drifted = await mcp_call(gateway, notes, "rug.save_note", {"text": "after"})
    assert drifted["atg_decision"] == "deny"
    assert drifted["drift"] is True

    research = lab.agent_token("research-assistant", ["web.read", "mail.send"])
    lab.reset_effects()
    fetched = await mcp_call(
        gateway,
        research,
        "web.fetch_page",
        {"url": "https://docs.nordlicht.example/status"},
        session="approval-test",
    )
    assert fetched["atg_decision"] == "allow"
    held = await mcp_call(
        gateway,
        research,
        "mail.send_email",
        {"to": "lena.vogel@nordlicht.example", "subject": "status", "body": "nominal"},
        session="approval-test",
    )
    assert held["atg_decision"] == "needs_approval"
    approval_id = held["approval_id"]
    decision = httpx.post(
        f"http://127.0.0.1:{lab.gateway_port}/api/approvals/{approval_id}",
        headers={"X-Approver-Token": "lab-approver"},
        json={"decision": "approved", "actor": "pytest", "note": "ok"},
        timeout=5,
    )
    decision.raise_for_status()
    released = await mcp_call(
        gateway,
        research,
        "mail.send_email",
        {"to": "lena.vogel@nordlicht.example", "subject": "status", "body": "nominal"},
        session="approval-test",
    )
    assert released["atg_decision"] == "allow"
    assert any(event["kind"] == "sent" for event in lab.effects("mail"))
