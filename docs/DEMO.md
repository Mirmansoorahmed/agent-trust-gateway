# Twelve-minute demo

Run the stack first.

```bash
docker compose up --build
```

Jaeger: <http://localhost:16686>. Approvals: <http://localhost:8080/approvals> with header or form token `lab-approver`.

The numbers you put on screen are the ones in [RESULTS.md](RESULTS.md), from `eval/results/summary.json`. Do not read a target from `DESIGN.md` as if it had been measured.

## 0:00–1:30 Problem

Tool descriptions are model instructions. `postmark-mcp` 1.0.16 added a silent BCC. A description can also change after a person has already approved the tool. Say what the gateway refuses to do: forward the agent's token, call a drifted server, or send onward after untrusted content without a person.

## 1:30–3:00 Architecture

Walk [docs/img/architecture.png](img/architecture.png): identity, pin, labels, OPA, token exchange, trace. Point at the trust boundaries in [ARCHITECTURE.md](ARCHITECTURE.md).

## 3:00–5:00 Without the gateway

The eval condition (a) talks to the servers with lab direct tokens. Show a rug-pull trial from `eval/results/trials.csv` where `scenario=t2_description`, `condition=a`, `success=true`. The effect log records the note after the description changed. Then show `t3_explicit_bcc` condition (a): the mail effect contains `bcc=attacker@evil.test`.

## 5:00–7:00 With the gateway

Same two scenarios, condition (c). `t2_description` is deny, `drift=true`, and `/api/alerts` has a manifest alert. `t3_explicit_bcc` is deny, reason "blind-copy recipient is not permitted", and the mail effect log is empty. Open the trace in Jaeger: span name `execute_tool rug.save_note`, attributes `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.agent.name`, `atg.decision`.

## 7:00–8:30 Identity

From the token matrix in the results: replaying the agent token against the mail server is rejected; an expired token is rejected; a downstream token for mail is rejected by the token-replay server; the matching downstream token is accepted and `token_use` is `downstream`.

## 8:30–9:30 Untrusted output

`t6_injection_colleague`, condition (c): the fetch is allowed, the following send is `needs_approval`, and no mail is sent because the run does not approve it. On the approval page, approve one held call from a live session and show the next identical call allowed. A different argument set stays held.

## 9:30–11:00 Results

Use the table in the README and [RESULTS.md](RESULTS.md). Say which rows are the scripted agent. If `eval/results/llm_sample.json` says skipped, say that out loud. Mention the Cisco YARA row: which tools it flagged, and which poisoned tools it did not.

## 11:00–12:00 Limitations

The linter is bypassable. The silent BCC residual is the honest gap. The gateway is a single point of failure (ADR 0001). Next measurement in a later project is detections on the same OTel spans, not a second gateway.
