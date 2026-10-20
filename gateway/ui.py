"""Minimal approval queue page. No build step."""

from __future__ import annotations


def approvals_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Agent Trust Gateway — approvals</title>
  <style>
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 2rem; color: #1c2430; background: #f4f6f8; }
    h1 { font-size: 1.4rem; margin-bottom: 0.2rem; }
    p.lead { color: #52606d; margin-top: 0; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border-bottom: 1px solid #e4e7eb; text-align: left; padding: 0.55rem 0.7rem; vertical-align: top; font-size: 0.92rem; }
    th { background: #102a43; color: white; }
    code { font-size: 0.82rem; }
    button { margin-right: 0.4rem; padding: 0.25rem 0.6rem; }
    .pending { color: #8a5a00; font-weight: 600; }
    .approved { color: #0b6e4f; }
    .denied { color: #9b1c1c; }
  </style>
</head>
<body>
  <h1>Approval queue</h1>
  <p class="lead">Risky tool calls wait here. The lab approver token is <code>lab-approver</code>. It is not a production secret.</p>
  <label>Approver token <input id="token" value="lab-approver" /></label>
  <button onclick="load()">Refresh</button>
  <table>
    <thead><tr><th>When</th><th>Agent</th><th>Tool</th><th>Arguments</th><th>Reason</th><th>Status</th><th></th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <script>
    async function load() {
      const token = document.getElementById("token").value;
      const response = await fetch("/api/approvals", { headers: { "X-Approver-Token": token } });
      const items = await response.json();
      const rows = document.getElementById("rows");
      rows.innerHTML = "";
      for (const item of items) {
        const tr = document.createElement("tr");
        const actions = item.status === "pending"
          ? `<button onclick="decide('${item.id}','approved')">Approve</button><button onclick="decide('${item.id}','denied')">Deny</button>`
          : "";
        tr.innerHTML = `<td>${new Date(item.created_at * 1000).toLocaleTimeString()}</td>`
          + `<td>${item.agent_id}</td><td><code>${item.tool}</code></td>`
          + `<td><code>${JSON.stringify(item.arguments)}</code></td>`
          + `<td>${item.reason}</td><td class="${item.status}">${item.status}</td><td>${actions}</td>`;
        rows.appendChild(tr);
      }
    }
    async function decide(id, decision) {
      const token = document.getElementById("token").value;
      await fetch("/api/approvals/" + id, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Approver-Token": token },
        body: JSON.stringify({ decision, note: "ui" })
      });
      load();
    }
    load();
  </script>
</body>
</html>
"""
