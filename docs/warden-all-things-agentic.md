# Warden: Making Autonomous AI Agent Fleets Governable

**All Things Agentic Hackathon · Fortified Enterprise Fleet**

> I created this article for the purposes of entering the All Things Agentic Hackathon.

AI agents are moving beyond chat. They can inspect systems, launch workloads, change configuration, and coordinate multi-step tasks. That is useful, but a prompt is not a security boundary. Warden is built around a stricter idea: autonomy should be enforceable at the execution boundary, with a human-visible trail of what happened and why.

## From agent intent to governed execution

Every tool call passes through Warden’s Google Agent Development Kit interceptor before the underlying tool is allowed to execute. The policy engine evaluates the action, identity, provider, region, machine type, requested lifetime, and cost. Unknown or ungoverned tools fail closed instead of receiving an implicit allow.

Warden combines:

- **Hard policy gates:** Disallowed regions, machines, actions, and ungoverned tools are blocked programmatically before a provider call.
- **Spend and TTL limits:** Launch cost comes from an authoritative rate card, while every compute action carries a bounded teardown lifetime.
- **Durable human approval:** High-impact actions park in a durable workflow until an operator reviews the exact request and grants permission.
- **Evidence that survives the run:** Decisions are sealed into a tamper-evident SHA-256 audit chain, while sensitive credentials are redacted before egress.

## Approval is part of the workflow

When a mission needs sign-off, Warden records the pending state instead of asking an operator to race a retry. The workflow parks durably, the operator reviews a preflight card with placement, cost, TTL, policy rules, and rollback information, and a verified approval resumes the work asynchronously. Approval identity is bound to the run and action, and hard policy denials remain non-overridable.

## A small demo with a large boundary

The end-to-end demo makes the boundary visible. A read-only inventory call is allowed. A launch in a disallowed region is denied. An ungoverned credential-modification tool is denied. A permitted GPU launch pauses for human approval, then resumes after the operator decision. Finally, the demo shows credential redaction and verifies the audit chain.

This is the point of the control plane: the agent can still be capable and useful, but capability does not silently become authority.

## Explore the implementation

Warden is open source. The public repository includes the policy engine, ADK interceptor, approval workflow, audit ledger, operator dashboard, tests, and demo:

https://github.com/Somnora/Warden
