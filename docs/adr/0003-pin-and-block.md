# ADR 0003 — Pin the tool list and block on drift

## Status

Accepted.

## Context

A rug pull is a catalogue that changes after someone has looked at it. An alert alone still lets the next call run.

## Decision

The first observation of an allowlisted server is pinned (canonical JSON of name, description and input schema, SHA-256). A later mismatch denies every tool on that server until an operator resets the pin. The mismatch is also stored as an alert.

Servers that are not allowlisted are not pinned. Admission is the control for those, not drift.

## Consequences

A legitimate tool edit requires a deliberate pin reset. That is friction, and it is the point. Auto-pin on first sight trusts whatever the server served at that moment, so a server that is malicious from the start must be caught by the linter, the allowlist or OPA, not by drift.
