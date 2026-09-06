# Development handoff for Gemini

Implement the credential lifecycle laboratory described in REQUIREMENTS.md and ACCEPTANCE.md. Read both documents in full before editing. This is an implementation task for a POC under poc/, not a request to rewrite the publication website or produce another conceptual plan.

The repository contains a functioning static article site. Preserve it and its existing deployment workflow. The lab has not been implemented. Do not assume a successful demonstration from article descriptions. The requirements and acceptance tests define intended behavior only.

Use real Vault, PostgreSQL, SPIRE, and Gitleaks services for the core. Build the small registry, intake, incident, and orchestration services needed to connect them. A reference local registry is intentional and must be labeled honestly. Optional iTop and GitLab profiles must use real products when claimed as working. ServiceNow verification requires authorized instance access; without it, deliver the adapter contract and report real integration as pending.

Start by checking the local environment, relevant repository instructions, Docker architecture, available resources, and official release compatibility. Record pinned versions, image digests, licenses, and provenance. Do not use fabricated image names or silently rely on paid functionality. Do not install unrelated global dependencies or modify unrelated Docker resources.

Work in the phases defined in REQUIREMENTS.md. First complete the legacy lifecycle through a real scanner event, registry enrichment, owner approval, Vault rotation, application restart, target checks, and redacted evidence. Then complete dynamic credentials, SPIRE identity, failure handling, and optional adapters. Continue through all mandatory core phases rather than stopping after scaffolding.

Use the proposed API and identifier contracts. Produce OpenAPI and JSON Schemas, database migrations, sample nonsensitive records, and adapter contracts. Keep raw secrets confined to approved runtime paths. Use generated local credentials, restricted bootstrap material, and scoped runtime identities. Never use the Vault bootstrap root token as the regular application or pipeline credential.

Make failure states visible. Preserve the difference between active and inconclusive validation, revoked credentials and surviving sessions, verified containment and healthy recovery, and a successful job and a closed incident. Test stale events, duplicate delivery, interrupted operations, wrong owners, wrong targets, and unavailable dependencies.

Do not replace real acceptance tests with mock success responses. Tests of simulated adapters must say mocked. Tests that cannot run must say skipped with a reason. Do not claim support for arm64, a SaaS integration, continuous availability, or production readiness without appropriate evidence.

The final handoff must contain runnable commands, prerequisites, tested platforms, measured resources, scenario results, evidence locations, outstanding limitations, and the exact source revision. Update poc/README.md so a new reader can run the verified core. Keep all generated credential material and sensitive fixtures out of Git and public artifacts.

Use clear prose and full sentences in documentation. Avoid repeated first person framing and statements explaining that these are notes for the reader. Keep technical syntax intact where required.

Completion means that all mandatory core requirements have implementation evidence and A01–A26 pass on a declared platform. Report optional adapter outcomes independently. Do not mark the whole POC complete if only the legacy path works.
