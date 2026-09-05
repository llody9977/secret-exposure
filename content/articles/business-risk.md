## A credential carries business authority

A secret is information used to authenticate, sign, or unlock access: an API key, database password, private signing key, or access token. Exposure occurs when it becomes available outside its intended trust boundary. That can happen in a public repository, but also in a private build log, a support attachment, or a developer's compromised machine.

The business consequence depends on the authority behind the credential. A token that reads synthetic test data has a different risk from one that can export customer records, change payment instructions, or publish software customers trust. The label “secret detected” does not tell a leader which situation exists.

A useful assessment connects four things: the exposed credential, the action it permits, the service or data affected, and the period during which misuse was possible. Add the conditions an attacker would still need to satisfy, such as network access or a separate approval. This gives the business a decision it can act on.

## Exposure is not proof of misuse

An exposed credential creates a route to access. It does not, by itself, prove that someone used that route or that customer data was lost. Conversely, an absence of suspicious events does not prove safety if relevant logs were never collected or have expired.

Keep those distinctions in the incident record. “Credential exposed; revoked; no misuse found in the available logs” is a defensible statement when supported by evidence. “No impact” is stronger and may be unjustified.

This matters commercially. Overstating harm can trigger unnecessary disruption. Understating uncertainty can delay containment and undermine later customer communication. Leaders need the current evidence, the remaining uncertainty, and the action being taken to reduce it.

## Follow the business consequence

Consider an illustrative payment service whose deployment job holds a production administration key. A compromised build dependency prints that key into a log. If the key remains valid and the target service accepts it from the attacker's location, the attacker may be able to change production. The cost can arise from fraudulent changes, service interruption during recovery, investigation, or delayed releases. These are possible outcomes of the scenario, not measured losses.

Now change the design: the deployment identity can update only one service, requires an approved production job, and expires shortly after use. Exposure still matters, especially while the job is running, but the potential scope and duration are smaller. This is why architecture belongs in the business conversation.

The March 2025 compromise of `tj-actions/changed-files` illustrates a specific route: malicious code extracted runner secrets and printed them into workflow logs. Public logs could expose those values to outsiders. The advisory does not establish that every repository using the action lost a usable credential. The lesson is that repository scanning alone does not address secrets released during execution. [GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

## Fund the outcome, not only the detector

A scanner is useful because it provides a signal that something may have escaped. That signal reduces risk only when it leads to an effective action. A team can close an alert while the original credential remains usable; the reporting improves while the access problem remains.

Business sponsorship should therefore cover a complete operating capability: named service owners, engineering capacity to change credential use, emergency revocation authority, and investigation across the affected systems. Buying detection without providing those capabilities can produce an expanding queue of known exposures.

The investment case should use the organisation's own services and dependencies. Identify the credentials whose misuse could interrupt critical operations or reach sensitive data. Estimate recovery effort with the teams who would perform it. Avoid presenting an industry breach average as the expected loss from a particular exposed key.

## The decisions leaders should make

Agree which services need the strongest access boundaries, who can authorise disruptive containment, and which legacy risks will be funded for removal. Require exceptions to have an owner, an expiry, and a practical compensating control. Ask for evidence that a critical credential can be invalidated and the service restored.

A useful leadership question is: **If this credential escaped today, could we identify its owner, limit the damage, and stop its use without improvising?** The answer directs the next investment more effectively than the number of alerts closed last month.

The next article turns these decisions into a plan with explicit ownership and a defined starting scope.
