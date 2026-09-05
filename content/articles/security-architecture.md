## I want the design to survive a credential escaping

The architectural question that matters to me is what happens after a credential crosses its intended boundary. Storage is part of the answer. I also need to understand who can use the credential, what actions it permits, how long it works, and how that authority can be withdrawn.

I would draw the path from build to production and identify the issuer, the receiving workload, the target service, and the evidence store. At each boundary, I would ask whether the workload needs the credential itself or only permission to perform a narrow operation.

A deployment job might need to release one service. I would want a specific justification before giving it unrestricted administration access.

## A vault changes storage without removing runtime risk

A secret manager can govern storage and retrieval. Once an application retrieves a value, the application and its execution environment are part of the protection boundary. A compromised process may misuse access it legitimately holds without ever writing the secret into source control.

This is why I would prefer separate workload identities over one credential shared across unrelated services. Separation can make both containment and attribution easier. If I revoke one identity, I want to understand which service stops working rather than discover a chain of hidden dependencies afterwards.

Kubernetes is a useful reminder to check the mechanism rather than rely on a label. Base64 encoding does not provide confidentiality. The official guidance calls for encryption at rest, restricted access to Secret objects, and protection after an application reads the value. I would check the actual cluster settings, including any managed service configuration. [Kubernetes guidance](https://kubernetes.io/docs/concepts/security/secrets-good-practices/).

## I would choose the access pattern deliberately

Where the platform and target support it, I would start by considering workload identity. AWS recommends temporary credentials through IAM roles for workloads. This reduces reliance on manually distributed persistent keys, although the role still needs appropriate permissions. [AWS IAM guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

External automation may be able to exchange evidence about a job for temporary target access. What matters to me is the trust policy behind that exchange. It needs to recognise the intended issuer, audience, and subject, including repository or environment conditions where supported. A broad policy could let the wrong job obtain a valid credential. [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

Some integrations will still require static credentials. I would want that constraint recorded together with a named owner, narrow permissions, monitored use, and a replacement procedure that has been exercised. Calling something legacy does not explain how its authority is contained.

## I would pay particular attention to the build environment

A privileged job may execute code maintained outside the organisation. I would separate processing of untrusted contributions from the stage that can obtain production access. I would also review who can change that stage and which approvals actually apply before it runs.

Pinning an approved action revision can support change control. It cannot establish that the selected revision is safe. I would still consider dependency review, runner isolation, and the outbound connections a privileged job needs.

The `tj-actions/changed-files` compromise is relevant because code inside a workflow extracted secrets from runner memory. My architectural inference is that protecting a value in storage does not make arbitrary code safe to execute beside it after retrieval. [GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

## Recovery belongs in the design

I would want to know what happens when the issuer or secret manager is unavailable. Can the workload continue briefly with access already issued? What happens at expiry? Which business operations need a documented degraded mode?

Rotation raises similar questions. Some consumers reload a secret automatically. Others require a restart or a new connection pool. If credentials can overlap, I need a defined overlap window and evidence that the old one stops working. If they cannot, I need a rehearsed cutover.

Temporary credentials limit the reuse window, but a compromised workload may continue obtaining new ones. I would therefore test how to stop issuance as well as how to handle access already issued. A design becomes convincing when those behaviours have been demonstrated in the deployed system.
