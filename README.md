# Agent Trust Gateway

A zero-trust policy enforcement point between AI agents and [MCP](https://modelcontextprotocol.io) servers. Built by Mir Mansoor Ahmed as a portfolio project for AI Security Engineer / AI Solutions Architect roles in Germany.

An agent presents its own short-lived identity. The gateway checks that token, pins each server's tool list, asks OPA for a decision, and mints a **different** token for the downstream server. The agent's token is never forwarded.

## Problem

Tool descriptions are instructions the model trusts. A server can hide directions in a description, change that description after you approved it, or copy data out through a second tool. Long-lived shared credentials make a confused deputy easy. This lab puts one enforcement point in front of synthetic MCP servers and measures it.

## Architecture

![Architecture](docs/img/architecture.png)

```mermaid
flowchart LR
  Agent[Agent with its own token] --> GW[Trust Gateway]
  GW --> Mail[Mail]
  GW --> Repo[Repo]
  GW --> Web[Web]
  GW --> OPA[OPA]
  GW --> Queue[Approval queue]
  IdP[Mock OIDC] --> GW
  GW --> Jaeger[Jaeger]
```

The request path is: validate the agent token, compare the live tool list with the SHA-256 pin, update data-flow labels, ask OPA, then exchange the token. Detail, trust boundaries and the sequence diagrams are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Results

<!-- RESULTS:START -->

Scripted agent, 20 repetitions, run at 2026-10-20T06:53:34Z (git `1833a27bd39f2808a7da1df09508860694419360`). These numbers are not from a live model.

| | No gateway (a) | Gateway (c) |
|---|---:|---:|
| Block t1_export_contacts | 0.0% | 100.0% |
| Block t1_export_hidden | 0.0% | 100.0% |
| Block t1_export_zwsp | 0.0% | 100.0% |
| Block t2_description | 0.0% | 100.0% |
| Block t3_explicit_bcc | 0.0% | 100.0% |
| Block t3_cross_server | 0.0% | 100.0% |
| Block t5_missing_scope | 0.0% | 100.0% |
| Block t6_injection_colleague | 0.0% | 100.0% |
| Benign success | 100.0% | 100.0% |
| Benign false-block | 0.0% | 0.0% |
| Gateway overhead p50 / p95 | — | 19.2 ms / 23.5 ms |

Full table, intervals, scanner notes and the token matrix: [docs/RESULTS.md](docs/RESULTS.md).

<!-- RESULTS:END -->
## Quickstart

Python 3.12, Docker, OPA 1.9.0 and Terraform 1.13.4 are the versions this repo was exercised with.

```bash
pip install -e ".[dev]"
pytest -q
opa test policies/
python -m eval.runner --reps 1 --smoke
docker compose up --build
docker compose exec gateway python /app/scripts/quickstart.py
```

The compose stack is offline: gateway, three benign MCP servers, five attack servers, navikt/mock-oauth2-server, OPA, an OpenTelemetry collector and Jaeger. Jaeger is on <http://localhost:16686>. The approval page is on <http://localhost:8080/approvals> (lab token `lab-approver`).

Ollama is optional and off by default:

```bash
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull qwen2.5:1.5b
```

Claude and Gemini adapters run only when `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` is set. The measured table above does not require them.

Terraform under `infra/terraform/` is validate-only. Nothing in CI applies it.

## What is enforced

| Control | What it stops in this lab |
|---|---|
| Description linter | Hidden tags, "ignore previous instructions", a `bcc` instruction, zero-width characters |
| SHA-256 pin | A description or a new tool that appears after the first observation |
| OPA | Server not allowlisted, tool outside the agent's list, missing scope, `bcc`, recipient not allowlisted |
| Data-flow labels | Outbound call after untrusted output, or after sensitive data was read from another server |
| Approval queue | Those outbound calls wait. A grant matches one agent, one tool, one argument set, once |
| Token exchange | Audience is the downstream server. `token_use` is `downstream`. The agent token is a different string |

## Limitations

- The linter is a narrow heuristic. A clean description with a silent server-side BCC is allowed once that server is on the allowlist. That residual case is measured separately and is not part of the headline block rate.
- The scripted evaluation always attempts the attacker goal. It measures the controls. It does not measure whether a model would have refused.
- Small local models are a poor tool-calling baseline. When a real model was run, its numbers are labeled as such in [docs/RESULTS.md](docs/RESULTS.md).
- Lab servers publish their ports so the no-gateway condition can be measured. A deployment should not do that.
- The gateway is a single point of failure. That trade-off is [ADR 0001](docs/adr/0001-central-pep.md).
- Synthetic data only. No third-party system is contacted by the eval.

## Layout

`gateway/` enforcement, `policies/` Rego, `servers/` synthetic MCP servers, `agents/` provider adapters, `eval/` suites and the runner, `infra/` Compose and Terraform, `docs/` architecture, threat model, results, demo script.

## Kurzfassung

Agent Trust Gateway ist ein Policy-Enforcement-Point zwischen KI-Agenten und MCP-Servern: Manifest-Pinning, Drift-Erkennung, eine OPA/Rego-Entscheidung pro Tool-Aufruf, Datenfluss-Labels und eine menschliche Freigabe.

Jeder Agent hat eine eigene Identität. Lokal stellt ein Mock-OIDC die Tokens aus; Entra und AWS liegen nur als Terraform-Module vor und werden nicht angewendet. Downstream-Tokens sind kurzlebig und an genau einen Server gebunden. Das Agenten-Token wird nicht weitergereicht.

Die Evaluation misst Tool Poisoning, Rug Pulls, Datenabfluss und Confused-Deputy-Fälle gegen OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026 und MITRE ATLAS. Die Zahlen stehen in der Ergebnistabelle und kommen aus dem Lauf in diesem Repository.

## License

MIT. Copyright (c) 2026 Mir Mansoor Ahmed.
