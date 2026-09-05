## Design the authority before the storage

A security architecture should explain what happens when a credential escapes. Storage is one part of that answer. The rest depends on what can use the credential, which actions it authorises, how long it works, and how access can be withdrawn.

Start with a trust-boundary diagram that follows a workload from build to production. Identify the issuer, the process receiving access, the target service, and the evidence store. At each boundary ask whether the receiver needs the credential itself or only the ability to perform a narrow operation. A deployment job may need permission to release one service; it rarely needs an unrestricted administration identity.

## A vault does not protect every use

A secret manager can control storage and retrieval. Once a process retrieves a value, that process and its execution environment become part of the protection boundary. A compromised application can misuse the access it legitimately holds, even if the secret was never committed to source control.

Avoid distributing a shared identity to unrelated applications. Give each workload a distinct identity and scope it to the target resources and operations it needs. Separation improves both containment and attribution: revoking one consumer should not require guessing which other services depend on its key.

For Kubernetes, base64 encoding does not provide confidentiality. The official guidance calls for encryption at rest and restricted access to Secret objects, and warns applications to protect values after reading them. Verify the actual cluster configuration, including managed-service settings, rather than assuming the object name guarantees protection. [Kubernetes guidance](https://kubernetes.io/docs/concepts/security/secrets-good-practices/).

## Choose the credential pattern deliberately

Prefer a platform-provided workload identity where the target supports it. AWS, for example, recommends temporary credentials through IAM roles for workloads. This reduces reliance on manually distributed long-term keys; permissions still need to be scoped. [AWS IAM guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

For external automation, federation can exchange an assertion about a job for a short-lived target credential. The trust policy must constrain the expected issuer, audience, and subject, including the intended repository or environment where supported. A broad trust policy may let an unintended workload obtain perfectly valid credentials. GitHub's OIDC documentation describes this exchange and the role of provider trust conditions. [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

Where federation is unavailable, use a managed static credential with a named owner, narrow permissions, monitored use, and a tested replacement procedure. Calling an integration “legacy” should explain a constraint, not remove the obligation to contain its authority.

## Treat the build system as a privileged environment

Build and deployment jobs often run code maintained outside the organisation. Separate jobs that process untrusted contributions from jobs that can obtain production access. Give production authority only to the smallest necessary stage, after the required reviews, and restrict who can change that stage.

Review dependencies and pin approved action revisions where supported. Pinning improves change control; it does not establish that the selected revision is safe. Isolate runners across trust boundaries and decide what outbound connections privileged jobs actually require. These are proposed design controls for reducing the opportunity to steal or misuse runtime credentials.

The `tj-actions/changed-files` incident shows why this boundary matters: code running inside a workflow extracted secrets from runner memory. The architectural inference is that safe storage does not make arbitrary code safe to execute beside retrieved credentials. [GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

## Design failure and recovery together

Specify behaviour when the identity provider or secret manager is unavailable. Can the workload continue briefly with an already-issued credential? What happens at expiry? Which operations fail closed, and which business functions need a documented degraded mode? Avoid a permanent emergency key that silently becomes the normal dependency.

Rotation also needs a consumer design. Some applications reload a secret automatically; others need a restart or new connection pool. If two credentials can overlap, define the overlap window and verify that the old one stops working. If they cannot, rehearse the coordinated change and its availability impact.

Short-lived credentials reduce the reuse window, but a compromised workload may keep obtaining new ones. Containment must include stopping issuance or disabling the workload's trust, with provider-specific treatment of sessions already issued. Design and test both paths.

## The architecture review should end with evidence

Request a per-workload access map, a negative test showing disallowed access is rejected, and a recovery exercise showing that an exposed identity can be contained. Include logging coverage and the emergency access procedure. A diagram becomes useful assurance when the deployed system behaves as the diagram claims.
