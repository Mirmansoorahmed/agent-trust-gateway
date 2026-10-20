# ADR 0005 — Local identity by default, cloud identity as Terraform only

## Status

Accepted.

## Context

The project has to run with no account and no API key. Entra and AWS are how the same pattern would look in a company, and they are also how a hiring review expects the design to be expressed.

## Decision

Docker Compose uses navikt/mock-oauth2-server. The in-process eval uses a local RSA issuer with the same claims (`agent_id`, `scope`, audience, short lifetime). `infra/terraform/entra` and `infra/terraform/aws` are optional modules. CI runs `terraform validate`. CI does not apply them.

## Consequences

The lab does not prove that a particular tenant's conditional access or IAM policy is correct. It proves the gateway's checks: issuer, audience, expiry, maximum lifetime, agent id and scope. Wiring a real issuer is a configuration change, not a second policy engine.
