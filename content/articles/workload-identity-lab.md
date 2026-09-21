## Removing a persistent password changes the dependency

A workload that receives temporary identity material can avoid carrying a manually distributed persistent password for a particular connection. That removes some copying and replacement work, but introduces dependencies on attestation, issuance, trust, and target authorization.

SPIFFE defines workload identity mechanisms, while SPIRE implements node and workload attestation and identity issuance. The resulting identity still needs to be accepted and authorized by the target. [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/), [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/).

The useful claim is therefore specific. A selected connection no longer depends on a persistent application password. It does not follow that the application cannot be compromised or that every downstream system has become passwordless.

## A valid identity is not permission to do everything

The local lab uses a caller and a protected API. Mutual TLS establishes their identities, while an authorization policy allows the expected caller to perform one harmless operation and denies a different identity or forbidden operation.

This separation matters because an authenticated workload can still have excessive permissions. A demonstration that only proves successful authentication would leave the central access decision untested.

NIST's application architecture guidance addresses authentication and authorization based on application and service identities. It supports treating identity as part of an access architecture rather than as the complete control. [NIST SP 800-207A](https://csrc.nist.gov/pubs/sp/800/207/a/final).

## Containment needs to address existing access

Stopping new issuance does not necessarily make every issued certificate or established connection ineffective immediately. A compromised workload may retain valid material until expiry, and connection behavior depends on the application and target policy.

The lab must therefore test issuance, fresh requests, and existing connections separately. A target authorization deny can provide an effective containment boundary, but its application to ongoing traffic needs evidence. Deleting a registration must not be presented as automatic instant revocation of all access.

This also changes the event model. The identity scenario can begin with evidence of workload compromise or unexpected access rather than a scanner finding. Forcing every case through secret scanning would hide the other signals the architecture needs to handle.

## Different applications can share one operating model

A legacy application may require a configuration update and restart. An integrated application may replace a dynamic database credential and its connection pool. The identity application may require issuance control and a target policy change.

All three can still use the same service records, owners, classifications, incident decisions, and evidence requirements. Their differences belong in the approved containment and recovery procedures. A common dashboard should preserve those differences rather than describe every action as rotation.

The [implemented lab](https://github.com/llody9977/secret_exposure/blob/main/poc/README.md) includes SPIRE issuance, renewal, and authorization checks alongside the two Vault paths. Each result still needs to show that the intended identity works, unintended access fails, and a compromised workload can be contained under the declared test conditions. A recorded demonstration does not establish that every workload or target behaves the same way.
