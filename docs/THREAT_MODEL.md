# Threat model

Assets: the synthetic mailbox, repository and files; agent credentials; the integrity of tool manifests.

Trust boundaries:

- agent to gateway
- gateway to each MCP server, untrusted until allowlisted and pinned
- gateway to the identity provider
- gateway to the human approver

The attacker in this lab controls an MCP server the agent is willing to call, or a tool argument the agent has been talked into sending. The attacker does not start with the gateway's signing key.

IDs were checked on 20 October 2026.

- OWASP LLM Top 10 2025, from the genai.owasp.org PDF dated 18 November 2024: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM06 Excessive Agency.
- OWASP Agentic Top 10 2026, from the genai.owasp.org PDF dated December 2025: ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities. ASI09's official name is Human-Agent Trust Exploitation. That entry includes overwhelming the human in the loop. Mapping approval fatigue to ASI09 is a partial match, not a claim that ASI09 is only about approval queues.
- MITRE ATLAS content v2026.09 (`ATLAS-2026.09.yaml`): AML.T0110 AI Agent Tool Poisoning, AML.T0109 AI Supply Chain Rug Pull, AML.T0086 Exfiltration via AI Agent Tool Invocation, AML.T0083 Credentials from AI Agent Configuration, AML.T0051 LLM Prompt Injection. AML.T0104 is not in this release. The publish-a-poisoned-tool idea is AML.T0115.002 AI Agent Tools, under AML.T0115 Publish Poisoned AI Artifacts. Mitigations cited below: AML.M0026, AML.M0028, AML.M0029, AML.M0030.

| # | Threat | Lab example | Control | OWASP LLM 2025 | OWASP Agentic 2026 | ATLAS 2026.09 |
|---|---|---|---|---|---|---|
| T1 | Tool poisoning | `<IMPORTANT>`, "ignore previous instructions", a zero-width `bcc` instruction | Linter, then OPA deny | LLM01 | ASI02, ASI04 | AML.T0110. AML.T0104 is absent; see AML.T0115.002 |
| T2 | Rug pull | Description or a new tool changes after the pin | SHA-256 pin, deny, alert | LLM03 | ASI04 | AML.T0109 |
| T3 | Cross-server exfiltration | BCC argument, shadowing, secret read then mail | Allowlist, recipient constraint, labels, approval | LLM02, LLM06 | ASI02 | AML.T0086 |
| T4 | Confused deputy / passthrough | Agent token replayed at another server | Audience, separate downstream token | LLM06 | ASI03 | No exact technique. Mitigation AML.M0026 |
| T5 | Over-privileged token | `mail.read` used to send, or a mail agent calling poison | Per-agent allowlist, per-tool scope, 10 minute cap | LLM06 | ASI03 | AML.T0083. Mitigations AML.M0026, AML.M0028 |
| T6 | Injection via tool output | Injected page or issue ISS-99, then send mail | Output flagged untrusted; outbound then needs approval | LLM01 | ASI01 | AML.T0051. Mitigation AML.M0030 |
| Fatigue | Approval flood | Nine sends after untrusted content | Eight approvals per minute, then deny | — | ASI09, partial, see above | AML.M0029 |

Out of scope: compromise of the machine running the MCP client (the CVE-2025-6514 class), prompt-injection classifiers beyond the narrow linter, and any claim of compliance.

The residual case that the controls do not stop: an allowlisted server whose manifest stays clean and whose implementation adds a BCC the arguments never contained. `shadow.send_email` is that case. It is reported separately in the results and is not folded into the T3 block rate.
