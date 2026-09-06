## The first decision concerns usable access

Deleting a secret from a file does not invalidate a copy someone already holds. GitHub puts revocation or rotation ahead of repository history cleanup for this reason. The visible exposure and the authority behind it need separate treatment. [GitHub cleanup guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

The response starts by establishing what the credential can reach, whether that access remains usable, and how it can be stopped. Credible exposure of privileged access deserves an urgent decision while the remaining facts are investigated. A complete timeline is useful, but waiting for one can prolong the period of possible misuse.

## Gathering evidence should not create more copies

The incident record needs the credential identifier, issuer, owner, affected service, observed location, and discovery time. Sensitive evidence belongs in restricted storage. Copying the raw value into ordinary tickets or chat can widen exposure during the response itself.

Discovery time also needs to remain distinct from the earliest possible exposure. A scanner may find a commit months after it was created. A provider may later revise the period affected by an incident. Recording what is known and what remains uncertain preserves the basis for later decisions.

Issuer metadata and approved administrative methods can help establish credential status. Trying an unknown value against production simply to see what it permits can have side effects or cross an authorization boundary. Validation needs its own scope and a method appropriate to the target system.

## Containment has to account for legitimate dependencies

Active misuse or highly consequential exposed authority may justify immediate invalidation despite service disruption. Where a brief transition is justified, introducing replacement access first may reduce downtime. The incident commander and accountable service owner need to make that tradeoff explicit, including the period when the exposed credential remains usable.

Replacing one value may still leave the source of compromise intact. A compromised runner, application, or federation trust can sometimes obtain fresh access after the original credential is revoked. Containment may therefore require isolation of the workload or removal of its ability to obtain new credentials.

Provider behavior matters. Disabling a key, removing a role assignment, and revoking a refresh token can have different effects on access already issued. Verification needs to establish the effective result at the target through an authorized method that cannot change business data.

## Investigation follows the authority into connected systems

The place that reports exposure is not necessarily where misuse would appear. A credential found in a repository may authorize access to a database, cloud account, or supplier service. Relevant evidence can include unexpected authentication, data access, permission changes, new credentials, and persistence in those systems.

CircleCI's January 2023 incident response involved customer secret rotation and investigation of connected systems. Its later report recommended examining activity from the reported initial compromise through customer rotation. That illustrates why the investigation boundary can extend beyond the reporting platform. It does not establish that every customer's connected service was compromised. [CircleCI incident report](https://circleci.com/blog/jan-4-2023-incident-report/).

The timeline needs to reflect both access opportunities and evidence limits. No suspicious events in incomplete logs cannot establish that no misuse occurred. The closure record should retain that distinction even when immediate containment is complete.

Signing and encryption keys also require attention to the trust or data they protect. Replacement does not undo past actions, retrieve copied plaintext, or automatically determine which signed artifacts remain trustworthy. Their consequences cannot always be resolved through the same procedure as an ordinary API token.

## Recovery needs evidence from the service

Replacement access should come from a trusted environment and be verified against important transactions, scheduled jobs, and operational tasks. The old access needs to be ineffective, and the compromised execution path must not be able to obtain a replacement through unchanged trust.

Exposed copies still need cleanup. Repository history rewrites can disrupt collaborators and cannot guarantee removal from every clone. Necessary forensic evidence should be preserved in restricted storage without allowing cleanup to delay containment. [GitHub cleanup guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

A useful closure record connects the original exposure to verified containment, the investigation performed, its limitations, and service recovery. Dismissing an alert records a tool state. It does not establish those outcomes by itself.

## The cause needs an owner after containment ends

A debug dump, shared identity, or overly privileged job may remain after the credential has been replaced. Without a separate owner for that underlying change, the same route can produce another exposure later.

Containment can be complete while recurrence prevention remains open. Tracking both makes that distinction visible and keeps the longer engineering work from disappearing when the immediate incident is closed.
