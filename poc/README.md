# Credential lifecycle laboratory

This directory contains implementation requirements. The lab is not implemented or tested yet. No Compose command in these documents is currently runnable. The published articles explain the design; they do not claim that the proposed demonstrations have succeeded.

Give Gemini [GEMINI_HANDOFF.md](GEMINI_HANDOFF.md), [REQUIREMENTS.md](REQUIREMENTS.md), and [ACCEPTANCE.md](ACCEPTANCE.md), together with the repository. Start with the handoff. REQUIREMENTS.md is the normative implementation contract. ACCEPTANCE.md defines the required evidence.

The deliverable is a local Docker Compose lab demonstrating intake, managed provisioning, detection, authoritative record correlation, owner triage, containment, recovery, and closure across three application categories. Real Vault, PostgreSQL, and SPIRE services are required. A local reference registry and incident application make the core reproducible without subscriptions. iTop, GitLab, and ServiceNow are separately identified integration profiles.

The core must not require ServiceNow, GitLab SaaS, cloud accounts, paid product features, or credentials from a reader's environment. It must not rely on the publication website to execute privileged operations.

## Files

[Requirements](REQUIREMENTS.md) define architecture, responsibilities, records, APIs, security boundaries, operational behavior, and implementation phases.

[Acceptance scenarios](ACCEPTANCE.md) define observable pass conditions, failure handling, and evidence requirements.

[Gemini handoff](GEMINI_HANDOFF.md) provides a ready to use development prompt and completion reporting rules.

## Completion status

Documentation is complete for development handoff. Core implementation, local execution, performance measurements, and real external adapter verification remain pending. A developer must update this status from observed results, preserving any remaining limitations.
