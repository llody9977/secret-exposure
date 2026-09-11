# POC remediation recheck

Reviewed September 9, 2026 against the original requirements and acceptance matrix and the September 8 assessment.

## Verdict

Not all findings are resolved. Several focused source changes are correct, but none of the eight original finding groups can yet be closed in full. The running deployment still uses earlier behavior, several attempted corrections preserve false success paths, and the revised metrics implementation introduces a confirmed runtime failure. The POC remains partially implemented and cannot support the README's 26/26 completion claim.

## Verified improvements

- Failed assertions now affect scenario results. An isolated A26 execution with controlled HTTP 503 responses returned FAIL, correcting the previous false PASS. The script also now exits nonzero when a scenario fails.
- The administrator-credential endpoint is removed from the current source, and the orchestrator no longer reads the bootstrap root-token file as an authentication fallback.
- Compose narrows the integrated application's bootstrap mount to its own read-only AppRole file.
- PostgreSQL initialization no longer declares the Vault database account a superuser. This changes new initialization only; an existing database needs a migration.
- GitLab is now an optional Compose profile and has a separate startup target.
- The base image is now Debian and the download logic selects amd64 or arm64. This is a source improvement, not a verified clean build.
- The runner derives its platform and HEAD revision, and its optional-result strings no longer assert successful contracts. The generated Markdown report still contains unsupported contract-success language.

## Current verification evidence

These checks did not rotate credentials, restart containers, reset data, or modify incident state.

| Check | Observed result |
| --- | --- |
| Live `/api/lab/access`, without authentication | HTTP 200; populated administrator-token and password fields still returned. Values were not printed or saved. |
| File access from running integrated app | Vault bootstrap key file still readable. |
| Live PostgreSQL role query | `vault_dba` still has superuser status. |
| Fresh import of revised metrics code inside control container | `psycopg2.InterfaceError: cursor already closed`. The existing web process still returns HTTP 200 from its earlier implementation. |
| Isolated revised A26, controlled HTTP 503 | FAIL, as required. |
| Isolated interrupted rotation, controlled issuer failure | Returned `reconciled_and_completed` with `external_reconciled: false`; requested verified/healthy database state. |
| Isolated revocation with absent lease metadata | Returned completed, containment verified, zero terminated sessions. |
| Current A13 method against live SVID metadata | FAIL after its eight-second wait because the serial did not change. This is a test-window failure, not proof that SPIRE never renews. |
| CI positive-scan shell handling | Scanner exits 1, 2 and container failure 125 all yield job exit 0; a clean scan exit 0 yields job exit 1. |
| Python syntax | All 19 application/script Python files parsed successfully. This does not establish functional correctness. |
| Latest saved full run | Still `run_20260908_122303`, ending September 8 at 12:23:12 UTC, before these fixes. All 50 exported events use `run_default`. |

The isolated executor checks used controlled dependencies and establish defects in the current control flow. They are not substitute acceptance evidence for the real services.

## Findings that still require action

### 1. Apply and verify remediation in the running deployment

The source removal of the access endpoint and mount restriction have not changed the running services. The web process serves its previously loaded code, and Compose mount changes require container recreation. Database initialization is explicitly skipped when `appdb` exists, so editing `init.sql` does not remove existing superuser privileges.

Repair the remaining source defects first, then recreate affected services and apply an explicit, scoped database migration. Verify that the old endpoint is unavailable, cross-service credential files cannot be read, and privileged roles have only required permissions. Replace the exposed disposable administrator credentials after closing the access paths. Do not use a data reset as a substitute for a documented migration.

References: `poc/docker-compose.yml:84`, `poc/docker-compose.yml:150`, `poc/postgres/entrypoint.sh:29`, `poc/postgres/init.sql:6`.

### 2. Server-enforced authentication is still absent

`approve_intake` still accepts a caller's identity from a header or body. A new comment defers authentication to production, but REQ009 and REQ025 require authentication in this lab. A requester can present another name consistently in both fields. Decision, execution, provisioning and internal credential routes still lack authenticated role enforcement. The control API still mounts the whole bootstrap directory and has the database management connection. Missing CA files still disable TLS verification in the issuer and integrated app.

Implement generated local users/sessions and scoped service identities, bind actor fields to authenticated principals, restrict mounts and privileged operations, and fail closed when trust material is missing. Test wrong-owner, requester impersonation, scanner execution, and cross-service access denial.

References: `poc/control/main.py:98`, `poc/control/main.py:395`, `poc/control/adapters/issuer.py:30`, `poc/apps/integrated/main.py:94`.

### 3. The old-password check tests a placeholder

The revised rotation path validates `OLD_EXPOSED_SECRET_PLACEHOLDER` instead of the actual previously issued password. A rejection of this arbitrary value proves nothing about the exposed credential. The restart-failure branch still marks containment verified without an old-password check.

Retain the actual old candidate through the restricted evidence path, establish that it authenticated before rotation, and verify its rejection afterward. Independently verify replacement access and recovery. The newly derived role reference also needs correction: provisioning records `database/roles/{service_id}-role`, while bootstrap creates `legacy-app-role`; the code does not establish that these refer to the same issued credential.

References: `poc/control/orchestrator.py:163`, `poc/control/orchestrator.py:229`, `poc/control/main.py:247`, `poc/scripts/bootstrap.py:151`.

### 4. Dynamic revocation still permits false containment and wrong-version targeting

The decision handler now fetches lease metadata, but it asks the integrated app for its current lease regardless of which credential version or service the incident concerns. A historical finding can therefore target a newer lease. Fetch errors are swallowed. The executor treats missing lease metadata as successful revocation and uses `revoked OR sessions_terminated > 0` as proof, although terminating sessions does not prove that fresh login is denied. Neither fresh authentication nor held-session behavior is checked after execution.

Resolve immutable lease and target metadata from the matched issued version. Missing or stale metadata must leave the operation incomplete. Block issuance at Vault, revoke the specific lease, and independently test old login and existing sessions. Application-local issuance blocking remains bypassable through the unauthenticated unblock endpoint.

References: `poc/control/main.py:432`, `poc/control/orchestrator.py:278`, `poc/control/orchestrator.py:285`, `poc/apps/integrated/main.py:231`.

### 5. Crash reconciliation can now repeat rotation and still ignores failure

The new reconciliation check calls `rotate_static_role`, which is a mutation. In a real crash after issuer rotation, this can rotate again instead of observing whether the original operation already succeeded. If that call fails, the code still marks the operation complete and the incident verified/healthy. The failure was reproduced with controlled dependencies.

Persist pre-action issuer metadata and operation intent. Reconciliation must read authoritative state and resume the unfinished rendering/restart/verification steps. A failed external check must not complete the operation. Credential-scoped locking, a transactional outbox, bounded retries and a real crash-after-side-effect test remain missing.

Reference: `poc/control/orchestrator.py:103`.

### 6. Closure and exception semantics still bypass evidence

Automatic closure no longer unconditionally changes ordinary containment to verified, which is an improvement. It still completes investigation and supplies default recurrence ownership when execution succeeds. Suppression/exception decisions can convert other containment states to not_applicable without independent evidence. The new `accepted_risk` and `unverified` values are not reconciled with the shared containment enum and original contract; A08 still expects not_applicable.

Keep exposure containment, risk acceptance, recovery disposition and investigation as distinct decisions. Use one closure validator for every path, require authenticated authority and evidence, and update shared models, UI, schema and tests together for any approved state change.

References: `poc/control/main.py:471`, `poc/control/main.py:527`, `poc/control/main.py:569`, `poc/control/models.py:21`, `poc/scripts/run_scenarios.py:395`.

### 7. Metrics now fail and their proposed definitions remain misleading

The function closes its cursor and connection at lines 678–679, then executes further queries at line 682. A fresh invocation reproduced the exception. Even after fixing that lifecycle, counting services with incidents is not counting successful scans: a clean successful scan would not contribute. `updated_at - created_at` measures the last record update, not the containment/recovery transition; later edits change the reported timing. The advertised interval is not applied to queries, the expected count still has an arbitrary minimum of ten, and freshness remains fixed.

Record scan attempts and scheduled expectations separately from findings. Measure durations using explicit transition timestamps, apply the reporting interval and include sample sizes and unknown values. Test a clean scan, missed scan, later incident edit and even-sized sample.

Reference: `poc/control/main.py:678`.

### 8. Provisioning still succeeds locally when Vault provisioning fails

Moving Vault calls before local inserts does not fix the failure path. The exception is caught as `simulated_or_skipped`, then active credential records and provisioned intake status are committed anyway. The value remains a deterministic synthetic KV API key while the metadata describes a database credential. The dedicated control policy also needs a successful provisioning test against the KV and policy operations it performs.

Make issuer failure a visible failed/pending operation with no false active credential. Provision the actual approved credential type and persist its real issuer reference, version and fingerprint. Provide retry/reconciliation for a successful issuer write followed by a local database failure.

Reference: `poc/control/main.py:213`.

### 9. The acceptance suite still does not prove the required behavior

A13 now compares serials, but waits eight seconds while the configured SVID TTL is one hour; it failed in the recheck. Use a deliberate test TTL and bounded renewal wait while checking allowed traffic. A14 still does not establish issuance denial and fresh/existing connection behavior. A23 adds a data read but does not restart or reset anything. A25 remains an HTML substring test. A26 adds another local request without restricting external connectivity. A20/A21 still do not exercise the specified concurrency/crash window. A06 still submits a synthetic event rather than scanning the issued credential through the lifecycle.

The positive scanner test searches for `leaks found`, which also occurs inside `no leaks found`. CI treats scanner execution errors as acceptable detection and still never starts the complete lab or runs the core suite. Use structured scanner reports, explicitly distinguish detection from tool failure, and execute each original scenario's actual behavior.

References: `poc/scripts/run_scenarios.py:513`, `poc/scripts/run_scenarios.py:578`, `poc/scripts/run_scenarios.py:800`, `.github/workflows/poc-ci.yml:41`.

### 10. Reproducibility, evidence and remaining architecture gaps

The implementation remains untracked while HEAD contains the specification. Dynamically reading HEAD does not identify the untracked implementation; Compose also still overrides source revision with the old constant. Evidence export remains unfiltered by run, lacks image/dependency lock checksums, and does not link assertions to specific events. No newer full-suite evidence was found. The README still claims fully implemented, 26/26 and an 8.5-second suite, while also saying the lab is not implemented.

The new base/download logic still needs a clean build and startup proof. Make does not build the image or Go binaries. The distribution-default PostgreSQL installation is not explicitly aligned to the startup script's hardcoded PostgreSQL 17 paths. Image digests, download checksums and complete dependency locks remain absent.

The legacy path still lacks a Vault Agent/tmpfs renderer and retains hot-swap behavior. The integrated path still lacks the specified pool and automatic renewal/replacement lifecycle. GitLab stage simulation remains; an API flag was added but the main UI does not consume a `simulated` marker. iTop and ServiceNow remain stubs, which is acceptable only as explicitly pending optional work.

References: `poc/Makefile:42`, `poc/Dockerfile.base:1`, `poc/postgres/entrypoint.sh:4`, `poc/docker-compose.yml:79`, `poc/scripts/run_scenarios.py:886`, `poc/control/gitlab_simulator.py:604`, `poc/README.md:25`.

## Recommended next sequence

1. Correct the metrics regression and the placeholder/missing-metadata/reconciliation success paths. Add focused negative tests that require failed or incomplete outcomes when evidence is unavailable.
2. Implement lab authentication, scoped mounts and privilege migrations. Apply the changes to the running services and verify denial before considering those findings closed.
3. Complete actual credential correlation, issuer-enforced containment, legacy rendering, dynamic lifecycle and identity tests. Keep investigation and risk acceptance separate from job completion.
4. Align models, acceptance expectations and UI states. Finish real scan, crash, concurrency, renewal, restart, offline and browser checks.
5. Build from a clean implementation snapshot, run the full suite, export correctly correlated evidence, and update the README from those results. Report each remaining gap explicitly rather than retaining 26/26 from the earlier run.

Only this recheck report was added during the assessment. Application behavior and running resources were preserved.
