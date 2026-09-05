## Reduce the amount of persistent authority

The long-term objective is to reduce how much reusable authority the organisation has to distribute and recover. Scanning remains useful as the environment changes, but fewer persistent credentials can remove entire classes of copying, ownership, and rotation work.

Workload identity is a way for a running service or job to authenticate using evidence of its identity and obtain bounded access. It changes the trust model. It does not remove the need to secure the workload, issuer, policies, and target system.

## Stabilise the current exposure first

Begin with known high-impact exposures, missing owners, and untested revocation paths. Establish which services and surfaces are covered. Ensure the operating team can distinguish a failed scan from a successful result and can reach the people authorised to contain access.

The exit condition for this phase is practical: important exposed access can reach an owner and be invalidated, and unresolved gaps are visible. Do not postpone urgent response while waiting for a future identity platform.

## Establish one supported pattern

Choose a service with meaningful risk and a feasible migration path. Define separate patterns for platform-native workloads, external automation, and integrations that still require static credentials. Give teams an implementation example, a support owner, and a recovery procedure for each approved pattern.

For cloud-native services, temporary role credentials can replace manually managed access keys. For suitable external jobs, federation can replace a stored cloud secret with a trust relationship. AWS and GitHub describe these respective mechanisms. The choice depends on the actual provider and workload, not on a general mandate to use one protocol everywhere. [AWS IAM guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

Validate the trust policy with both allowed and denied cases before widening the rollout. A short token lifetime cannot compensate for allowing the wrong job to request a fresh token whenever it wants.

## Migrate by risk and dependency

Prioritise persistent credentials with broad authority, many copies, or difficult recovery. Then consider feasibility: target support, ownership, consumer changes, and supplier constraints. The best first migration often combines a worthwhile reduction in risk with a pattern other teams can reuse.

For each migration, capture the old access path, new trust conditions, target permissions, lifetime, logging, and emergency containment. Test the workload with its old credential unavailable. After verifying service health, invalidate and remove the old access. Leaving the original key active as an indefinite fallback defeats much of the intended reduction.

Where migration cannot proceed, improve the existing arrangement and retain a time-bound exception. A smaller, isolated static credential with dependable revocation can be a useful interim improvement even when full federation is unavailable.

## Use a 90-day plan as a starting hypothesis

For an organisation beginning this work, the following is an illustrative planning sequence, not a universal deadline. Adapt it to incident urgency, service complexity, and available delivery capacity.

During the first 30 days, select critical services, assign owners, identify exposed authority, and exercise a revocation path. Produce a baseline with explicit coverage gaps and response responsibilities. Advance when those responsibilities work in practice.

During days 31–60, pilot the supported credential or identity pattern, improve new-exposure prevention, and repair the main operational obstacles. Produce evidence of a successful replacement and a failed unauthorised-access test. Advance when the pilot is supportable by the operational team.

During days 61–90, expand to the next services, retire replaced credentials, and review exceptions and recurring causes with management. Produce a capability profile and a prioritised backlog. Expansion should be guided by demonstrated readiness, not merely by reaching a calendar date.

## Keep the new trust system governable

Federation moves work into trust-policy management and workload security. Review who can change the repository, environment, issuer configuration, and target role. Monitor unexpected issuance and access, and test how to stop a compromised workload from obtaining more credentials.

Plan for issuer outages and emergency access. Keep emergency authority narrow, monitored, and exercised. A permanent broad fallback used whenever automation is inconvenient can recreate the original problem under a different name.

## Make the next decision concrete

Choose one business service. Name the owner. Identify the most consequential persistent credential it uses and the route by which that credential could escape. Decide whether to remove it, narrow it, or improve its containment first. Define the evidence that will show the change worked.

Repeat that decision across the estate. The path forward is a reduction in persistent authority and avoidable exposure, supported by response and governance that continue to work as the technology changes.
