# Credential lifecycle POC requirements

## Purpose and delivery boundary

REQ001. Build a reproducible local lab in this directory. Demonstrate that response speed depends on information, authority, and recovery capability established before exposure. Scanning is one event source, not the controller of the entire lifecycle.

REQ002. Preserve the publication application and its build. Do not replace the website or deploy the lab to GitHub Pages. Runtime code, data, and integration configuration belong under poc/. Add an independent CI workflow with no access to production credentials.

REQ003. These are proposed requirements, not results from a completed implementation. Choose compatible released component versions during implementation, record the official sources and licenses, pin image digests and dependency versions, and commit the lock records. Do not silently substitute products or claim untested platforms work.

REQ004. The mandatory core uses Docker Compose, real Vault, real PostgreSQL, real SPIRE, a scanner, a response orchestrator, a local registry and incident UI, and three demonstration applications. Use Python with FastAPI and PostgreSQL for the custom control services, Go with a maintained SPIFFE library for the identity demonstration, and Gitleaks as the initial scanner. Alternate libraries may be selected with a recorded compatibility reason. The core registry is explicitly a reference implementation, not a simulation of ServiceNow or iTop.

REQ005. Deliver optional real integration profiles separately. GitLab executes approved response jobs. iTop supplies service context and incident records through an adapter. ServiceNow supplies enterprise CMDB and incident integration when a user provides a suitable instance. These profiles are not prerequisites for a passing core. Unavailable external access must produce a documented unverified status, never a fabricated success.

## Component responsibilities

| Component               | Required responsibility                                                                                                                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registry API and UI     | Own service context, owner groups, classification, intake decisions, approved access, and consumer relationships.                                                                                 |
| Incident API and UI     | Own assignment, triage, approval, containment progress, investigation status, exceptions, and closure. It may share a deployment with the registry but must use distinct records and permissions. |
| Orchestrator and worker | Own workflow state, correlation, leases on work items, retry policy, and evidence references. Use a durable PostgreSQL queue and transactional outbox.                                            |
| Vault                   | Own secret material, access policies, database role configuration, leases, and audit events.                                                                                                      |
| SPIRE                   | Own node and workload attestation, registration, and SVID issuance.                                                                                                                               |
| Protected service       | Enforce target authorization and expose harmless lab operations whose outcomes can be tested.                                                                                                     |
| Scanner adapter         | Detect controlled fixtures and send normalized finding metadata. It has no revocation authority.                                                                                                  |
| Validator               | Test only configured lab targets using read only operations. Distinguish rejection from unavailable evidence.                                                                                     |
| Application supervisor  | Apply an approved restart or reload to one known local consumer. It must not accept arbitrary commands or expose the Docker socket to ordinary services.                                          |

REQ006. Use separate PostgreSQL databases and roles for control records and application data, even if one local server hosts them. Applications must not read control records. A Vault database management account must not be an application identity. Define and test its minimum necessary permissions, including any session containment operation used by the lab.

REQ007. Use explicit stable service_id, consumer_id, credential_id, credential_version_id, finding_id, incident_id, and operation_id values. A Vault path is a reference, not a durable substitute for a service identity. Never trust an owner, secret path, command, or destination URL supplied by a finding without resolving it against authoritative records.

## Authoritative records and intake

REQ008. Intake must precede issuance. Required fields are service name and stable ID, accountable owner group, active operational contact, fallback group, environment, classification, business criticality, application category, target resource, requested permissions, consumer list, lifetime policy, replacement mode, expected restart behavior, recovery procedure ID, and exception status. Lab classification values are synthetic policy categories, not regulatory classifications.

REQ009. Reject incomplete intake with field errors and no issuance side effects. An authorized approver must approve access requirements. A developer cannot approve their own request by changing request JSON or an HTTP header. Requests and decisions retain actor identity, UTC time, policy revision, and record revision.

REQ010. Service and ownership records are versioned. Retiring an owner or changing a consumer must invalidate or flag the relevant operational readiness check. The core allows one accountable owner group and multiple consumers per credential. Unknown or ambiguous ownership routes to a designated security fallback queue, never to an invented owner.

REQ011. Credential records hold issuer type, issuer reference, service and consumer references, credential type, permissions summary, lifetime, rotation mechanism, status, and version lineage. Actual lease IDs are restricted operational metadata. Raw passwords, private keys, tokens, and connection strings containing passwords must not enter the registry, tickets, ordinary logs, or evidence exports.

REQ012. Persist a keyed HMAC fingerprint of the exact credential material and a canonicalization version when the approved provisioning path handles the value. Retain historical fingerprints so a finding for an old version can be resolved. Store the HMAC key separately from the registry and expose comparison through an authenticated service, not public enumeration. Never assume Vault audit hashes equal these application fingerprints. For dynamic issuance, the application or local issuance broker must register the issued instance before reporting ready. This broker is a trusted credential handler and must be documented as such.

REQ013. A scanner sidecar or restricted adapter may transiently process raw findings. Strip or quarantine secret material before sending general events. If later validation requires the candidate, put it into a narrowly accessible short retention evidence store and pass an opaque reference. Reference access must be audited. Reject expired references as inconclusive evidence. Do not pass secrets in job arguments, pipeline variables, tickets, or URLs.

## Application categories

REQ014. Legacy application. Supply a small application that reads username and password from a protected configuration file only at process startup. It must contain no Vault client code. Use a Vault database static role for its dedicated PostgreSQL account. An agent renders the file onto a tmpfs volume with restrictive ownership. An explicit supervisor applies the approved restart. The agent identity can read only that service's role. The application cannot read the agent token or another service's file.

REQ015. Legacy rotation is a coordinated cutover, not a promise of uninterrupted operation. Rotate through Vault's supported database role operation, wait for the new version to be rendered, restart the consumer, verify a new connection and a harmless transaction, and test rejection of the previous password. Measure actual interruption. Do not restore an exposed password as a recovery shortcut. If a restart fails, containment and recovery must remain separately visible.

REQ016. Include a documented counterexample for an application whose credential truly cannot be changed. Record an exception with owner, residual authority, compensating control, and exit condition. Do not fake transparent rotation for an unmodifiable credential. This is a negative scenario, not a fourth mandatory application implementation.

REQ017. Integrated application. Use a dedicated Vault dynamic database role with bounded read access and a short configurable lab lifetime. The application or trusted local broker obtains the credential after authentication, records the issued instance, and creates a connection pool. The application demonstrates lease renewal within allowed limits and replacement when renewal is unavailable. Expose health and harmless business operation endpoints without values or tokens.

REQ018. During integrated containment, block new issuance to the affected workload before revoking the exposed lease when compromise is modeled. Perform lease revocation through Vault. Test new authentication using the old credential and test a connection established before containment. If sessions survive, invoke the narrowly scoped target session termination procedure or report partial containment. A Vault HTTP success alone is insufficient evidence.

REQ019. SPIFFE application. Run a real SPIRE server and agent with workload attestation, not hardcoded certificates labeled as SPIFFE. Issue X.509 SVIDs to a caller and protected API. Use mutual TLS and a target authorization policy that permits the expected SPIFFE ID to read one synthetic resource and denies another identity or forbidden operation. The protected API is the target for this path. Its downstream storage, if any, must not be described as automatically passwordless.

REQ020. Demonstrate SVID renewal while the application runs. Trigger a compromised workload scenario independently of the secret scanner. Prevent new issuance and apply an authorization deny at the target. Test both fresh and existing connections. Explain and measure whether existing SVIDs remain cryptographically valid until expiry and how the target stops authorized use. Removing a registration alone must not be presented as instant certificate revocation. Do not conflate authentication with authorization or claim the whole environment is zero trust.

## Bootstrap and deployment

REQ021. Implement a scripted bootstrap stage with a single node persistent Vault using local TLS and a lab CA. Generate initialization material locally into restricted ignored storage. Configure audit logging and least privilege policies. Use bootstrap authority only for setup, then remove it from application and ordinary worker environments. Document seal and unseal behavior across restarts. Do not use a constant published root token as normal application access.

REQ022. Use isolated AppRole credentials with response wrapping or another documented supported authentication path for the non-SPIFFE core consumers. AppRole SecretIDs are bootstrap secrets, not evidence that the lab is secretless. Deliver them through restricted volumes, renew or replace their access deliberately, and verify cross-service denial. Use distinct identities for provisioning, read access, validation, and containment.

REQ023. Pin and document a supported SPIRE node attestation method. If a Docker workload attestor requires a Docker socket, confine that privilege to a separate attestation component, document its host control implications, and never mount it into scanners, applications, or the web UI. Prefer an attestation design with narrower host privileges where practical. Do not silently run every container privileged.

REQ024. Publish only the necessary local UI endpoints on 127.0.0.1. Keep database, Vault, identity, and execution traffic on separated Compose networks with only required membership. Validate TLS certificates. No TLS verification bypass as the default. External network access is needed for installation; core acceptance scenarios must not depend on external services once images are present.

REQ025. Provide seeded local identities for requester, approver, service owner, and responder. Generate credentials locally rather than placing reusable passwords in documentation. Session authentication and role checks must be server enforced. Record failed authorization attempts. Local lab authentication is not an enterprise SSO claim.

REQ026. Provide targets for make doctor, make bootstrap, make up, make demo-legacy, make demo-integrated, make demo-identity, make test, make evidence, make down, and make reset. Doctor validates Docker Compose, architecture, ports, resources, and required files without dumping credentials. Reset is confined to this Compose project and requires explicit confirmation before deleting its data. Never run a global Docker prune.

REQ027. Target Linux amd64 and Docker Desktop arm64. Verify each platform or mark it unverified. Record actual peak memory, bootstrap time, and test time on tested hardware. Begin resource planning at 4 CPUs and 8 GiB available for the core, but treat this as a provisional budget to measure, not a proven minimum. Provide a separate measured budget for the optional GitLab profile and flag image emulation requirements.

## Findings, validation, and incident state

REQ028. Use Gitleaks against an isolated lab repository or local log fixture. Provide a custom pattern for the lab format and label its coverage honestly. Never claim that recognizing a custom format proves generic database password detection. Include positive and negative fixtures. Fixture generation can deliberately copy one disposable local credential after issuance. Fixture files and raw scanner output must be ignored by Git and excluded from exported evidence.

REQ029. Normalize events with schema_version, event_id, source, detected_at, observed_at, locator, fingerprint or restricted candidate_ref, detector identity and version, and optional claimed service hint. The hint is untrusted. The orchestrator resolves the authoritative target, credential version, owner, and classification. Events require authenticated producers, replay protection, size limits, and validation of all identifiers.

REQ030. Validation results are active, invalid, inconclusive, or unsupported. Network failure, timeout, missing evidence, and permission to validate being denied are not invalid credentials. Limit validators to explicit internal targets and harmless operations. Validate no arbitrary hostnames from an event. Add a wrong-target test. Validity is not proof of incident scope, misuse, or absence of persistent sessions.

REQ031. Track independent status fields. Correlation is matched, unmatched, or ambiguous. Triage is pending or decided. Containment is pending, running, verified, partial, failed, or not_applicable. The last value requires an authorized, evidenced determination that the finding contains no credential or represents no applicable exposure. Recovery is pending, healthy, degraded, or failed. Investigation is open or complete_with_limitations. Case status is open or closed. Unknown ownership and inconclusive validation must not silently close a case.

REQ032. The normal path is detection, durable event acceptance, correlation, validation, owner assignment, triage decision, action approval or policy authorization, execution, containment verification, recovery verification, investigation review, then closure. Emergency policy may authorize containment before full enrichment, but only for a known target with explicit preauthorization. Record the policy revision and scope. Do not require a human approval for a scenario whose policy already authorizes the operation.

REQ033. Closure of a confirmed exposure requires verified containment, a recorded recovery disposition, investigation completed with stated limitations, and an owner for recurrence work. A false positive closure requires independent evidence, an authorized decision, and an explicit not_applicable containment disposition. Unsupported or inconclusive validation cannot justify that disposition. An invalid old credential does not prove there was no past exposure. Track and review that history before closing. A case with failed containment cannot become closed simply because the pipeline exited successfully.

REQ034. Operations use an idempotency key derived from incident, credential version, approved action, and policy revision. Lock by affected credential and use compare-and-set state transitions. Duplicate delivery must not repeat rotation. A stale finding must not rotate the current credential without a fresh approved decision. Retry bounded transient failures with backoff. After exhaustion, retain a visible failed step and recovery instructions. On worker restart, resume from persisted intent and reconcile external state before repeating side effects.

## API and integration contracts

The following routes are required interfaces for the reference implementation. Exact JSON Schemas and OpenAPI files must be produced during implementation. IDs and status values must use a single shared model.

| Interface                          | Required contract                                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| POST /api/intakes                  | Accept the REQ008 fields and an idempotency key. Return a draft or validation failure, without issuing credentials. |
| POST /api/intakes/{id}/approve     | Require an approver and expected record revision. Store an immutable approval record.                               |
| POST /api/intakes/{id}/provision   | Enqueue approved provisioning. Return operation ID, never raw secret material.                                      |
| GET /api/services/{id}             | Return authorized metadata and current revision.                                                                    |
| POST /api/findings                 | Accept the REQ029 event. Return the existing incident for duplicates or a durable acceptance identifier.            |
| POST /api/incidents/{id}/decisions | Require a permitted actor, reason, action enum, and expected incident revision.                                     |
| POST /api/operations/{id}/execute  | Require scoped execution identity. Resolve target and parameters server side from approved immutable intent.        |
| GET /api/incidents/{id}/evidence   | Return only redacted evidence references available to the caller.                                                   |
| GET /api/metrics                   | Return measures with scope, interval, denominator, missingness, and evidence freshness.                             |

REQ035. Use consistent 401, 403, 404, 409, and 422 semantics. Never accept a shell command, Vault path, SQL statement, or arbitrary callback URL as a user-selected action parameter. Validation and execution callbacks must be authenticated and bound to the operation and executor identity.

REQ036. Define RegistryAdapter, IncidentAdapter, SecretIssuerAdapter, IdentityAdapter, ValidatorAdapter, and ExecutorAdapter boundaries. The local executor and optional GitLab executor invoke the same approved operation contract. Changing an adapter must not change containment or closure semantics.

REQ037. GitLab profile must provide real project setup, runner registration, and pipeline configuration. Use a narrowly bound job identity token for Vault or the orchestrator, verifying issuer, audience, project, and protected execution context. Account for the selected edition's feature availability. The free baseline may use explicit supported API authentication instead of a premium secrets keyword. Jobs receive operation IDs, not raw credentials or administrator tokens. Bind execution to a reviewed code revision. Untrusted merge request jobs cannot execute containment. A successful job reports evidence but cannot unilaterally close an incident.

REQ038. iTop profile must create or import a reproducible service model and map owner/support groups, service relationships, classification extensions, credential metadata references, and incident state. Include mapping documentation, setup migrations, rollback, and read/write contract tests. Do not store secret values in iTop. Validate the actual API and license requirements of the selected release before choosing an image. No invented official container image.

The active registry adapter is authoritative for service context and ownership. Select exactly one registry authority per deployment. The local control database retains workflow state, version correlations, and revisioned context snapshots, not a competing editable copy of external ownership. External incident IDs map to stable local incident IDs. Reconcile changes and report stale snapshots during adapter outages. Do not silently fall back to local ownership while claiming the external registry remains authoritative.

REQ039. ServiceNow profile must document the specific CMDB/CSDM and incident table mapping applicable to the supplied instance, required roles and plugins, reference field resolution, pagination, rate limiting, assignment rules, and API authentication. Confirm capabilities against that instance. Contract tests alone must be labeled as such. No claim of real integration until a disposable authorized instance has passed a read, assignment, update, and evidence-link round trip. This adapter remains pending if no instance is provided.

## Evidence, metrics, and presentation

REQ040. Persist UTC event timestamps and durations. Each evidence event includes scenario_id, run_id, incident_id, operation_id, actor, action, status, service_id, credential_version_id where relevant, source revision, component versions, and redacted result. Store detailed sensitive diagnostics separately with restricted access and retention. Redacted JSONL and a human-readable report must be exportable without secrets.

REQ041. Measure intake completeness, owner resolution coverage, successful scans divided by expected scans, detection to assignment, detection to verified containment, rotation to healthy application, recurrence, and migration completion. Retain open cases, failures, unknown inventory, and inconclusive validation. Use medians and tail values only with sample sizes. Separate known exposure time from detection time. Small synthetic lab results are not production SLAs or scanner benchmark claims.

REQ042. Map demonstrated outcomes to NIST CSF 2.0 functions, with each relationship labeled as an implementation interpretation. Keep detailed SP 800-53 mapping in documentation and verify each selected control's current wording before claiming alignment. SPIFFE is an identity specification, SPIRE an implementation, and ATT&CK a threat knowledge base. None is a substitute for proof of control effectiveness or regulatory compliance.

REQ043. A minimal local white UI with blue accents must show intake, service details, consumer relationships, incident timeline, owner decision, containment/recovery distinction, and evidence. It must be responsive and keyboard usable. No simulated green status. Show real pending, failed, and unknown states. No extra dashboard library or elaborate design system is required.

## Delivery phases

Phase 1 establishes Compose, bootstrap, schema, role checks, intake, provisioning, and the legacy path. Complete the legacy scenario and its failure tests before expanding.

Phase 2 adds the integrated application with real dynamic issuance, renewal, scoped revocation, pool replacement, and session checks.

Phase 3 adds real SPIRE attestation, SVID renewal, authorization, and identity containment tests.

Phase 4 completes the failure matrix, metrics, evidence export, clean installation instructions, and independent CI tests.

Phase 5 supplies optional GitLab and iTop profiles. ServiceNow is implemented and tested only when suitable authorized access is available. Report each adapter independently.

At each phase, record changed files, exact commands run, observed results, remaining limitations, and next dependencies. Do not rewrite completed phases merely to add another tool. The first four phases constitute a complete core release; optional adapter claims require their own evidence.

## Primary references

The requirements above are proposed engineering decisions. The following sources establish relevant product mechanisms; they do not certify a deployment outside the documented laboratory scope.

[Vault database secrets](https://developer.hashicorp.com/vault/docs/secrets/databases) documents static and dynamic role mechanisms.

[Vault Agent templates](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template) documents file rendering and refresh behavior.

[Vault leases](https://developer.hashicorp.com/vault/docs/concepts/lease) describes renewal and revocation semantics.

[SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) describes attestation and issuance. [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/) describes identity documents and isolation assumptions.

[GitLab Vault integration](https://docs.gitlab.com/ci/secrets/hashicorp_vault/) describes job identity integration. [GitLab installation requirements](https://docs.gitlab.com/install/requirements/) supports separate resource planning.

[iTop source](https://github.com/Combodo/iTop) describes the CMDB and service management product. [ServiceNow CSDM](https://www.servicenow.com/docs/r/servicenow-platform/common-service-data-model-csdm/ci-relationships.html) describes service relationships.

[Gitleaks](https://github.com/gitleaks/gitleaks), [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20), and [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) support detector and evidence mapping work.
