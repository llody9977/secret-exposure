# Credential lifecycle laboratory

This directory contains the normative implementation, automated test suite, and evidence generation framework for the credential lifecycle laboratory specified in [REQUIREMENTS.md](REQUIREMENTS.md) and [ACCEPTANCE.md](ACCEPTANCE.md).

Core acceptance is verified by the complete behavioral checks in [ACCEPTANCE.md](ACCEPTANCE.md). The runner reports failed and incomplete checks separately; a passing subset does not establish completion.

The deliverable is a local Docker Compose lab demonstrating intake, managed provisioning, detection, authoritative record correlation, owner triage, containment, recovery, and closure across three application categories:
- **Legacy (Static credentials):** Vault KV / static roles with supervised application process restart and database login verification.
- **Integrated (Dynamic credentials):** Vault dynamic database credentials with lease renewal, pool replacement, and active session termination.
- **Identity-First (SPIFFE/SPIRE):** SPIFFE SVID issuance, automated renewal, mutual TLS (mTLS), and dynamic target authorization policy containment.

The core is designed to run locally after downloading images and dependencies. A26 verifies external routing is blocked and local traffic succeeds. External service accounts are not required for the core.

## Files

[Requirements](REQUIREMENTS.md) define architecture, responsibilities, records, APIs, security boundaries, operational behavior, and implementation phases.

[Acceptance scenarios](ACCEPTANCE.md) define observable pass conditions, failure handling, and evidence requirements.

[Gemini handoff](GEMINI_HANDOFF.md) provides background context and completion reporting rules.

## Completion status

The current source passed a full local run on September 11, 2026: **A01–A26 PASS, 0 FAIL, 0 INCOMPLETE**. See [the acceptance report](evidence/run_20260911_123355_65d59697/report.md). Historical reports predate later changes and must not be used to assess the current implementation.

- Mandatory A01–A26 outcomes are recorded independently. Incomplete required checks cause a nonzero runner exit.
- X01–X05 represent optional external enterprise adapters requiring live integration environments or authorized access. GitLab and iTop may be local; ServiceNow requires an authorized instance. Their skips do not fail the core and do not prove that the adapters work.
- Each run exports a content hash and per-file source hashes, including untracked source, plus correlated events, assertions, and the report. Generated secrets and runtime data are excluded from the source inventory.
- Clean installation, full-stack restart/unseal/reset, and complete UI keyboard workflows are exercised as isolated behavioral checks. A database restart or browser login check alone cannot satisfy those complete scenarios.

## Runnable Commands

All core operations are encapsulated in standard `make` targets inside `poc/`:

```bash
# Verify system prerequisites, tools, and security boundaries
make doctor

# Build local image and Linux SPIFFE binaries, then initialize the lab
make bootstrap

# Launch Docker Compose services (PostgreSQL, Vault, SPIRE, Control Plane, Supervisor, Apps)
make up

# Execute standalone category demonstrations
make demo-legacy      # A06: Static credential exposure, Vault rotation, supervisor restart, verification
make demo-integrated  # A09, A10: Dynamic credentials, lease renewal, pool replacement, session termination
make demo-identity    # A12, A14: SPIFFE Workload API attestation, mTLS, dynamic policy denial

# Install optional browser verification dependency and Chromium
make browser-setup

# Run focused regression tests without network access
make unit-test

# Run core scenarios and report incomplete checks honestly
make test

# Export evidence package
make evidence

# Stop containers
make down

# Confined cleanup of lab containers, volumes, and bootstrap secrets
make reset
```

## Local sign-in

Bootstrap generates local accounts and unique passwords in the restricted `.bootstrap/auth_credentials.json` file. Open the UI and sign in with the account appropriate to the action. The acceptance runner reads that local file and exchanges credentials at `/api/auth/token`; it cannot mint or grant its own role. Keep this file private and out of evidence packages.

## Architecture & Security Boundaries

- **Network Isolation:** Three distinct Docker networks:
  - `control-net`: Bridges the Control Plane API to PostgreSQL, Vault, and Supervisor.
  - `app-net`: Bridges demo workloads to Vault and PostgreSQL.
  - `spire-net`: SPIRE server/agent communication.
  - Network membership is not per-service authorization; scoped credentials and authenticated administration enforce service boundaries.
- **Workload Attestation:** Workload API attestation via SPIRE with PID namespace sharing (`pid: "service:spire-agent"`) and distinct UIDs (`1001` caller, `1002` service) without mounting the Docker socket or running containers privileged.
- **Secret Redaction:** Control plane API and evidence logging never expose raw secrets or bootstrap tokens. Only cryptographic HMAC fingerprints and non-secret version identifiers are stored and returned.
- **Static Publication Site Integrity:** The Next.js/vinext publication site at repository root remains completely untouched and builds cleanly (`npm run check`).
