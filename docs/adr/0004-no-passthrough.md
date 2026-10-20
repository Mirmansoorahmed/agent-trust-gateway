# ADR 0004 — Do not forward the agent token

## Status

Accepted.

## Context

The MCP authorization spec (2025-06-18) binds tokens to an audience and forbids token passthrough, so a server cannot replay the agent's credential against a different resource.

## Decision

The gateway validates the agent token for audience `agent-trust-gateway`. It then mints a new RS256 token whose audience is that one server, whose `token_use` is `downstream`, and whose lifetime is 60 seconds. The two strings are compared and the call is refused if they are equal.

Downstream servers reject any token whose use is not `downstream` (or `direct` in the lab baseline).

## Consequences

A server only ever sees a credential for itself. Stealing it does not yield the agent's identity at the gateway. The lab's direct tokens exist only so the no-gateway condition can run; they use a different issuer.
