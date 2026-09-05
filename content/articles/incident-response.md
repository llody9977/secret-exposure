## Stop usable access, not just visible exposure

Removing a secret from a file does not invalidate it. Anyone who already obtained the value may still be able to use it. GitHub therefore puts revocation or rotation ahead of repository history cleanup in its guidance for removing sensitive data. [GitHub cleanup guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

The first response decision is about access: what authority may have escaped, whether it is still usable, and how to stop it. Treat credible exposure of privileged access as urgent while investigating the details. Do not wait for a perfect timeline before taking proportionate containment action.

## Establish the facts without spreading the value

Create an incident record with the credential identifier, issuer, owner, affected service, observed location, and discovery time. Use a restricted evidence store for sensitive material. Keep raw secrets out of ordinary tickets, email, and chat, where the response itself could create more copies.

Separate the first observed exposure from the earliest possible exposure. A scanner may discover a commit months after it was created; a vendor notice may widen the investigation period later. Record uncertainty rather than assigning a convenient timestamp.

Prefer issuer metadata and approved administrative methods to establish whether a credential is active. Do not test an unknown credential by using it against production simply to see what happens. A validity check can have side effects, cross an authorisation boundary, or expose the value to another service.

## Choose containment with the service owner

If there is active misuse or highly consequential exposed authority, immediate invalidation may be necessary despite disruption. Where there is no observed abuse and a brief controlled transition is justified, a replacement-first cutover may reduce downtime. The incident commander and accountable service owner should make that tradeoff explicit, including the remaining exposure window.

Contain the mechanism that can create more access. A compromised runner, application, or federation trust may continue obtaining fresh credentials after one token is revoked. Disable or isolate the affected execution path and review the issuer's treatment of existing sessions.

Follow provider-specific semantics. Disabling an API key, removing a role assignment, and revoking a refresh token do not necessarily have identical effects on previously issued access. Confirm the effective result at the target, using an authorised test that cannot change business data.

## Investigate the authority behind the credential

Review the systems the credential could reach, not only the repository where it appeared. Look for unexpected authentication, data access, permission changes, new credentials, configuration changes, and persistence. Connect events through available identity, source, and timing information while acknowledging gaps.

CircleCI's January 2023 incident response required customers to rotate affected secrets and investigate connected systems. Its later incident report recommended examining activity from the reported initial compromise through customer rotation. This is a concrete example of why containment and investigation extend beyond the system that first reports exposure; it does not establish that every customer's connected service was compromised. [CircleCI incident report](https://circleci.com/blog/jan-4-2023-incident-report/).

If the exposed material is a signing or encryption key, assess the associated trust and data consequences separately. Replacing an authentication secret does not undo actions already taken. Likewise, a key change cannot retrieve copied plaintext or automatically establish which signed artefacts remain trustworthy.

## Recover, then close with evidence

Restore the service with replacement access from a trusted environment. Verify critical transactions, background jobs, and operational tasks. Check that the original access is ineffective and that the attacker cannot mint a replacement through an unchanged trust relationship.

Clean up exposed copies with care. History rewrites can disrupt collaborators and cannot guarantee deletion from every clone or external copy. Preserve restricted forensic evidence before cleanup where needed, and keep containment moving in parallel. [GitHub cleanup guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

A defensible closure record states what was exposed, the containment method and verification time, the investigation performed, its limits, the service recovery evidence, and the recurrence-prevention work. “Alert dismissed” is a tool state. Closure is an evidenced judgement that the response objectives have been met.

## Fix the route that caused the incident

Assign the underlying change to a delivery owner. That may mean removing a debug dump, separating privileged jobs, replacing a shared identity, or changing a supplier integration. Track this work even when the immediate incident is closed. Otherwise, the organisation becomes good at repeatedly replacing credentials while preserving the same route to exposure.
