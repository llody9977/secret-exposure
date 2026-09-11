# POC assessment against the original plan

Reviewed on September 8, 2026 against `poc/REQUIREMENTS.md`, `poc/ACCEPTANCE.md`, and `poc/GEMINI_HANDOFF.md` from commit `ad909262cc11b16549a333f4d42c9a389b76c37b`.

## Decision

The implementation follows the planned component choices and broad workflow, but does not meet the original completion contract. It is a useful, partially implemented demonstration with real services. It is materially weaker than the plan in authorization, credential isolation, containment verification, durable execution, reproducibility, and evidence integrity. Keep the working components and repair those foundations before adding features or declaring the core complete.

The original plan deliberately required proof that access stopped working, recovery succeeded, and the incident could legitimately close. Several implemented paths replace that proof with status assignments. This is a material change to the purpose of the lab, even though the interface and integration surface have expanded.

## Basis and limits

Reviewed the current working tree, the normative documents, the scenario runner, saved evidence, service implementation, bootstrap, Compose, and CI configuration. The implementation files are currently untracked; HEAD contains the specification, not this implementation. The saved evidence nevertheless identifies HEAD as its source revision.

Read-only live checks confirmed that the control API and containers are running; the SPIFFE caller returned HTTP 200 for the allowed resource and HTTP 403 for the forbidden operation. An unauthenticated request to `/api/lab/access` returned populated Vault root-token and GitLab root-password fields. The values were not printed or included in this report. A file-access check confirmed that the integrated application can read the Vault bootstrap key file.

An isolated execution of the existing A26 test method, using a controlled HTTP 503 response, recorded a failed assertion and still returned scenario PASS. This checks the test runner's reporting logic, not the actual offline behavior of the lab.

The saved run `run_20260908_122303` reports 26 passing scenarios and contains 44 passing assertions. Those recorded assertions do not establish the full acceptance requirements. Its 50 exported events all use `run_default`, rather than the manifest's run ID. No full acceptance rerun, credential rotation, service restart, reset, clean installation, or browser accessibility audit was performed during this assessment.

## What to retain

- Real Vault, PostgreSQL, SPIRE, and Go SPIFFE integration, with separate caller and protected service applications.
- A local registry, intake and incident APIs, version/fingerprint records, separate containment and recovery fields, and an evidence export structure.
- Working SPIFFE mutual TLS and request authorization. The protected resource checks policy on each request, which is useful for enforcing changes on reused connections; the required fresh-versus-existing connection test is still missing.
- The supervisor's fixed consumer allowlist, loopback host bindings, and SPIRE attestation design without a Docker socket in ordinary services.
- Additional application views and GitLab integration scaffolding as potential teaching aids. They do not compensate for unverified control outcomes.

## Material findings

### 1. Completion reporting is unreliable

`poc/scripts/run_scenarios.py:35` records a false assertion without failing the scenario. Scenario methods subsequently assign PASS if no exception occurs; A26 at line 822 demonstrates this directly. The runner also lacks an explicit nonzero exit for failed results. A13 reads one certificate serial rather than observing renewal; A23 searches Compose text rather than testing restart/reset; A25 searches HTML strings rather than checking keyboard use; A26 performs an ordinary HTTP request rather than disconnecting external services.

The CI workflow does not run A01–A26 and suppresses doctor and positive-scanner failures with `|| true`. Its green result cannot establish core acceptance. Optional contract-success descriptions are inserted as fixed strings without executing those contract tests in `run_all`.

Affected contract includes A01–A26 and the handoff's prohibition on replacing real acceptance with simulated success.

### 2. Authorization and secret isolation contradict the plan

`poc/control/main.py:1380` exposes bootstrap administrator credentials without authentication. `approve_intake` at line 98 accepts actor identity from a caller-controlled header or body; matching two caller-controlled names is not authentication. Decisions, execution, provisioning, and internal credential-handling routes lack the required authenticated role boundaries.

`poc/docker-compose.yml:150` mounts the entire bootstrap directory into the integrated app. The same broad directory is mounted into the control API. `poc/control/orchestrator.py:52` falls back to the bootstrap root token. PostgreSQL initialization creates `vault_dba` as a superuser, and the control API receives its connection details. Missing CA files cause TLS verification to be disabled in the issuer and integrated application.

These fail the intent of REQ006, REQ009, REQ021–025 and A03/A05/A22. Loopback publication does not establish permissions between workloads or users.

### 3. Containment and closure can be declared without evidence

`poc/control/orchestrator.py:189` labels the legacy outcome verified without performing the stated old-password rejection test. Rotation always selects `legacy-app-role`, rather than deriving the issuer role from the approved credential relationship.

For dynamic containment, operation decisions do not populate the lease/username parameters used by the executor. At line 223 a missing lease becomes `True`; session termination is skipped when no username exists. The saved A10 result reports verified containment with zero terminated sessions, without checking either fresh login or the held session afterward. Even a false revocation result is not used to prevent a verified outcome.

`poc/control/main.py:448` can turn containment into verified and recovery into healthy while closing a case. The execute endpoint invokes this helper automatically after completion, inserting investigation and recurrence fields without the required review. Recording an unmodifiable-credential exception also becomes not_applicable containment, although accepting residual risk does not establish that exposure is inapplicable.

These materially weaken REQ018 and REQ030–034, especially A06/A10/A18.

### 4. Crash recovery and concurrency are not implemented to the planned standard

`poc/control/orchestrator.py:96` completes an interrupted operation by updating local records, without consulting Vault or the target. The interruption flag is set before an issuer action, rather than killing a worker after the external side effect. The operation-row lock is released before external execution, running operations remain eligible, and locking is not by affected credential. The schema has no transactional outbox or durable worker-lease mechanism.

A20 exercises sequential duplicate finding delivery, not concurrent execution. A21 therefore does not prove safe recovery from the required failure window. Implement REQ034's persisted intent, credential lock, bounded retries and external reconciliation before trusting repeat execution.

### 5. Provisioning and the legacy pattern diverge from the intended lifecycle

`poc/control/main.py:187` creates active credential metadata and marks the intake provisioned before calling Vault. It stores a deterministic synthetic API key in KV while recording a database-role reference, and still returns provisioned when Vault setup fails. A06 registers an invented lab token and submits finding JSON rather than scanning the actual issued database credential through the complete path.

There is no Vault Agent service rendering to a protected tmpfs. The orchestrator writes credentials to a host bind mount. The legacy app now offers an in-process credential hot-swap endpoint at `poc/apps/legacy/main.py:153`, weakening its role as the startup-only counterexample. Keep any hot-swap demonstration as a separately labeled capability, and restore the required baseline.

### 6. Dynamic credentials and workload identity are only partially demonstrated

The integrated app uses individual database connections, not the promised pool. Renewal and replacement require explicit endpoints rather than a lifecycle that handles expiry or renewal denial. Registration errors do not prevent readiness. Issuance blocking is a mutable application boolean with an unauthenticated unblock endpoint, not a denial enforced by Vault against the compromised identity.

SPIRE and target authorization are real, but identity containment only changes the target policy. It does not prevent further SVID issuance. A13 does not wait for renewal, and A14 does not separately establish issuance denial, retained-certificate validity, and fresh/existing connection outcomes. These remain incomplete under REQ017–020 and A09–A14.

### 7. Metrics and provenance are not reliable observations

`poc/control/main.py:656` hardcodes expected scans to 10, completed scans to 9, containment median to 4.2 seconds and recovery median to 6.8 seconds. They are not measurements. Evidence generation hardcodes the source SHA and platform, lacks the required image/dependency lock checksum, and does not associate the exported events with the run.

Replace these with observations from recorded events and explicit missing values. Bind evidence to the exact implementation snapshot and link each assertion to its supporting events. Until then, do not use the displayed metrics to evaluate effectiveness.

### 8. Packaging and optional integrations have expanded beyond the verified core

`poc/Dockerfile.base:1` uses an unrelated unpinned `latest` base and downloads arm64-only tools. Compose requires a local image without a build definition; the documented make sequence does not build it or compile the Go binaries. A fresh checkout cannot reproduce the current working directory through those commands alone. The amd64 CI runner does not validate this arm64 runtime path.

GitLab is included in the default Compose startup rather than an optional profile, and `make up` invokes its setup. Real GitLab API calls exist, but `poc/control/gitlab_simulator.py:515` can synthesize stage progression from elapsed time when a runner is absent. iTop and ServiceNow remain stub adapters. External access may legitimately leave optional acceptance pending, but fixed contract-success messages and simulated stages are not integration evidence.

## Recommended action order

1. **Correct the claim and stop exposing bootstrap authority.** Mark the core partially implemented; remove administrator-secret responses and root-token fallback; restrict mounts and runtime database authority; enforce authenticated identities and roles. Replace exposed disposable lab credentials after the boundaries are repaired.
2. **Make failures trustworthy.** Derive scenario status from every mandatory assertion, fail the process on test failure, and add a negative regression check for reporting. Remove fixed metrics, simulated operational success, automatic investigation completion, and evidence-free containment. Preserve failed, unknown and partial outcomes.
3. **Complete one real legacy lifecycle.** Approved intake must create the actual target credential and record its fingerprint. Run Gitleaks on a controlled exposure of that credential, resolve its owner and version, execute the approved rotation, render through the restricted agent, restart, test both passwords, and measure business recovery. Exercise an actual restart failure.
4. **Complete dynamic and identity containment.** Persist and resolve lease metadata, block issuance at the issuer, revoke and probe fresh/held sessions, implement renewal and pool replacement, and authorize recovery. Observe SVID renewal and test issuance denial plus fresh and existing connections.
5. **Make execution and evidence durable.** Add credential-scoped locking, transactional work delivery, crash reconciliation, real concurrency tests, run-linked evidence, immutable revision references and a requirement-to-test trace.
6. **Reproduce and reassess.** Supply pinned architecture-aware builds, a clean-install path and independent CI running the real core suite. Test reset in an isolated project and verify offline behavior. Keep GitLab optional; label simulations visibly and report each real integration separately. Run the browser checks before claiming A25.

Accept the core only when A01–A26 have the evidence defined in the original matrix on a declared platform. Additional features should wait until that gate is met. Repair is preferable to a full rewrite because the real service integrations and much of the record structure are reusable.
