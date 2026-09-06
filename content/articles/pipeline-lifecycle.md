## A response pipeline needs context before authority

A pipeline can run a revocation command without knowing whether it targets the right credential or whether the application can recover. Reliable automation needs an approved operation tied to authoritative service and credential records.

That connection begins at intake. The service owner, classification, required access, consumers, and replacement behavior should exist before issuance. Provisioning can then create the appropriate access and record its relationship to the service without giving routine users the raw value.

When a scanner later reports a finding, the workflow can resolve those relationships instead of reconstructing them during an incident. This is the part of integration that determines whether detection can lead to a timely decision.

## The event should identify a case rather than carry a command

A normalized finding needs a source, time, location, detector version, and a protected way to correlate the credential. A claimed service name is a hint to verify. It should not grant the event sender control over an owner assignment, network destination, or Vault path.

The orchestrator resolves the actual target and records the proposed action. Execution receives an operation identifier and obtains narrowly scoped authority. This makes retries, approval, and evidence traceable to a stable decision.

GitLab documents job identity integration with Vault. The selected edition and configuration determine which mechanism is available. A reusable administrator token stored in pipeline variables would introduce another broad credential dependency. [GitLab Vault integration](https://docs.gitlab.com/ci/secrets/hashicorp_vault/).

## Replacement depends on the consumer

For a legacy application, an external agent can render managed configuration while the application remains unaware of Vault. The application may still require a restart before it uses the replacement. Vault Agent supports template rendering, but successful rendering is not proof of application recovery. [Vault Agent templates](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template).

An integrated application can handle credential renewal and connection replacement directly. The workflow still needs to verify old access and any session established before containment. Changing an issuer record alone cannot establish the effective state at the target.

The operation therefore needs separate containment and recovery outcomes. A credential can be invalidated while the service remains unavailable. That condition deserves an open recovery task rather than a misleading success status.

## One service can make the complete sequence visible

Consider a local reporting service whose database password is read from a file at startup. Before provisioning, its approved record identifies the reporting owner, synthetic data classification, database account, consumer process, and restart procedure. Vault creates and manages the access. An agent delivers the protected configuration without requiring a developer to copy the password.

The proposed exercise deliberately exposes that disposable local credential in an ignored fixture. Gitleaks produces a finding, and a restricted adapter correlates its fingerprint with the registered credential version. The workflow obtains the service context from the registry and assigns the incident to its owner. An approved validator checks only the registered database using a harmless operation. An unavailable database produces an inconclusive result that remains visible.

After authorization, the executor rotates the registered Vault role, waits for the agent to render the replacement, and restarts the known consumer. Verification checks a new application transaction and rejection of the old password. Any existing database session is checked separately. The incident records the containment result and the measured service interruption, with investigation still required before closure.

The default Docker lab uses a small local registry and incident service so the exercise can run without an enterprise subscription. An optional iTop adapter can supply real service management integration. ServiceNow can supply the corresponding enterprise records when an authorized instance is available. In each deployment, one selected system owns service context and ownership. The orchestrator retains identifiers and revisioned evidence rather than becoming a second editable source of ownership.

## Failure handling is part of the demonstration

Duplicate findings should lead to the existing case rather than repeated rotation. An old finding should resolve to the historical credential version rather than automatically revoke its replacement. A worker interrupted after an external action must reconcile that action before retrying it.

Validation failure also needs an explicit path. A timeout is inconclusive, and unmatched ownership requires fallback routing. Neither should close the case as harmless.

The [POC implementation contract](https://github.com/llody9977/secret_exposure/blob/main/poc/REQUIREMENTS.md) defines these boundaries and the [acceptance scenarios](https://github.com/llody9977/secret_exposure/blob/main/poc/ACCEPTANCE.md) define how they must be tested. They are requirements for a future working lab, not results from one already executed.

The intended evidence connects intake, issuance, detection, owner decision, target verification, and healthy service behavior. A successful pipeline becomes one record within that chain rather than the definition of incident closure.
