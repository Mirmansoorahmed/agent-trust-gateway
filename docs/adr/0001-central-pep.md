# ADR 0001 — One gateway in front of every MCP server

## Status

Accepted.

## Context

Each agent could enforce policy itself. That spreads the pin, the label state and the token exchange across every client, and a new client can forget them.

## Decision

All tool calls in the supported deployment go through one gateway. The gateway is the policy enforcement point: authentication, manifest pin, labels, OPA, token minting, approval and traces.

## Consequences

A caller that can reach a server directly bypasses the gateway. The lab publishes server ports on purpose so the no-gateway condition is measurable. A real deployment should not.

The gateway is also a single point of failure. Availability of every tool depends on it. That is the cost of having one place that can block a rug pull.
