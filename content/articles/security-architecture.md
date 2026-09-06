## The design needs to account for access after retrieval

A secret manager can protect a credential in storage and control who retrieves it. Once a workload receives the value, the workload and its execution environment become part of the protection boundary. Code running there may be able to use the access even if the credential never appears in source control.

That changes the architecture question. Where a secret is stored matters, but so do the permissions it carries, the processes that receive it, and the conditions under which the target accepts it. A deployment job that needs to release one service does not automatically need authority to administer the whole environment.

Following the path from issuer to workload to target makes those decisions visible. It also exposes where responsibility changes hands. The platform may govern retrieval while the application controls what happens to the value afterwards. Protection needs to continue across that handoff.

## Shared credentials make containment harder

Suppose several services use the same database identity because it was convenient during an early deployment. Access records may identify that shared account without establishing which service made a request. Replacing the credential also becomes a coordinated change across consumers that may reload configuration differently.

Separate workload identities reduce that coupling. Permissions can reflect each service's purpose, and stopping one identity need not interrupt unrelated consumers. The separation still has to be reflected in effective policy. Different identity names achieve little if each receives the same broad access.

Kubernetes provides a useful example of why configuration needs closer examination than the object name. Base64 encoding does not provide confidentiality. The official guidance calls for encryption at rest, restricted access to Secret objects, and protection after an application reads the value. Actual cluster settings, including managed service configuration, determine whether those protections are present. [Kubernetes guidance](https://kubernetes.io/docs/concepts/security/secrets-good-practices/).

## Temporary access depends on a sound trust policy

Where supported, workload identity can reduce reliance on manually distributed persistent credentials. AWS recommends temporary credentials through IAM roles for workloads. The role still needs permissions appropriate to the job. [AWS IAM guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

External automation may be able to exchange an assertion about its identity for temporary target access. The important boundary sits in the trust policy. It needs to constrain the issuer, audience, and subject, including the intended repository or environment where supported. Otherwise, an unintended job may obtain a valid credential through an overly broad trust relationship. [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

Some suppliers will continue to require static keys. That limitation makes ownership, narrow permissions, monitoring, and tested replacement more important. A legacy designation explains why a preferred pattern is unavailable. It does not explain how the remaining authority is controlled.

## Privileged jobs need a deliberate execution boundary

A build process may execute code maintained outside the organization. Giving that execution production authority creates a dependency on the behavior of everything running beside the credential.

Processing untrusted contributions separately from privileged deployment stages reduces that exposure path. The boundary also depends on who can modify the privileged workflow and whether the required approvals apply before access is issued. Reviewing an application change is insufficient if another route allows the deployment definition to be altered without equivalent control.

Pinning an approved action revision supports change control, but does not establish that the chosen revision is safe. Dependency review, runner isolation, and restrictions on unnecessary outbound connections address other parts of the execution risk.

The `tj-actions/changed-files` compromise demonstrated extraction of secrets from runner memory. The architectural implication is that secure storage cannot make arbitrary code safe to execute beside credentials after retrieval. [GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

## Recovery is part of the architecture

An issuer outage raises questions that normal operation can hide. A workload may continue briefly with access already issued, then fail when that access expires. The design needs to account for that transition and any business function that requires a documented degraded mode.

Rotation creates a similar dependency on consumer behavior. Some applications reload a secret automatically. Others require a restart or a new connection pool. Where credentials can overlap, the transition needs a defined end and evidence that the old access fails. Where overlap is impossible, a coordinated cutover needs to be rehearsed.

Temporary credentials also leave a distinction between stopping existing access and preventing new issuance. A compromised workload may keep obtaining fresh credentials until its trust or execution is disabled. Provider behavior determines what happens to sessions already issued.

A convincing review therefore needs more than a diagram. It needs evidence that intended access works, unintended access is rejected, and a compromised identity can be contained without leaving an unexplained path back in.

## Authoritative records connect the control systems

The service catalog or CMDB owns the service context and its accountable owner. The secret manager owns credential material and issuance. An incident system owns response decisions. Stable identifiers connect these records without copying secret values into a ticket or inventory. ServiceNow can occupy the service and incident roles, but the architecture depends on maintained relationships and usable interfaces rather than a particular product.

The design also needs a credential version relationship and a record of consumer behavior. A detected value may belong to an earlier version, while a consumer may still hold an old connection. Resolving both prevents an automated response from rotating unrelated current access or declaring containment before the target rejects the exposed authority. Validation must use approved targets and treat unavailable evidence as inconclusive.
