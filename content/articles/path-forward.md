## I want less persistent authority to look after

The direction that makes sense to me is to reduce how much reusable authority has to be distributed, protected, and recovered. Scanning remains useful, but removing a persistent credential can also remove some of the copying and rotation work associated with it.

Workload identity changes how a service proves who it is and obtains access. It does not remove the need to protect the workload, issuer, trust policy, and target system. I would see the migration as a change in the trust model rather than the disappearance of security work.

## I would stabilise the current situation first

Known consequential exposures, missing owners, and untested revocation paths would come first. I would establish which services and surfaces are covered, whether failed scans are visible, and whether responders can reach someone authorised to stop access.

The outcome I want from this stage is practical. Important exposed access can reach an owner and be invalidated. Any gaps remain visible. A future identity platform is not a reason to delay containment today.

## I would build one pattern that others can use

I would choose a service where the risk reduction matters and migration is feasible. Platform workloads, external automation, and static supplier integrations may need different patterns. Each should have an implementation example, a support owner, and a recovery procedure.

Temporary role credentials can replace manually managed keys for suitable cloud workloads. Federation can replace a stored cloud secret for external jobs where the target supports it. AWS and GitHub describe these respective mechanisms. I would choose based on the actual workload and provider rather than require one protocol everywhere. [AWS IAM guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

Before expanding the pattern, I would test both allowed and denied access. A short token lifetime does not help enough if the wrong job can request a fresh token whenever it wants.

## I would prioritise both risk and feasibility

Broad authority, many copies, and difficult recovery would make a persistent credential worth examining early. I would then consider the target's capabilities, consumer changes, ownership, and supplier constraints.

For each migration, I want to retain the old access path, the new trust conditions, permissions, lifetime, logging, and emergency containment. I would test the service with the old credential unavailable and then invalidate and remove it after confirming service health.

An indefinite fallback key would concern me. The new identity path may be working while the original authority remains usable. I would want an explicit end to that overlap.

Where migration is blocked, a narrower static credential with better isolation and dependable revocation can still be an improvement. I would keep the remaining constraint and the next decision date visible.

## A 90 day sequence can help me organise the work

I would use a 90 day plan as a starting hypothesis rather than a promise that every organisation can follow the same timetable. Incident urgency, service complexity, and delivery capacity should shape the pace.

During the first 30 days, I would focus on critical services, owners, known exposure, and one exercised revocation path. I would want a baseline that shows coverage gaps and response responsibilities. The useful milestone is that the responsibilities work in practice.

During days 31 to 60, I would pilot the supported access pattern, improve prevention of new exposure, and address the operational obstacles. I would look for a successful replacement and evidence that an unauthorised access attempt is rejected. The operational team needs to be able to support the result.

During days 61 to 90, I would expand to the next services, retire replaced credentials, and review exceptions and recurring causes. I would leave this stage with a capability profile and a prioritised backlog. Readiness should determine expansion rather than the calendar alone.

## The new trust still needs governance

Federation moves some of the work into trust policies and workload protection. I would review who can change the repository, deployment environment, issuer configuration, and target role. I would monitor unexpected issuance and test how to stop a compromised workload from obtaining more access.

I would also plan for issuer outages and emergency access. A broad permanent fallback that becomes the normal response to inconvenience could recreate the original dependency.

## I would return to one concrete decision

I would choose a service, name its owner, and identify its most consequential persistent credential. I would then ask whether the next useful step is to remove that credential, narrow its authority, or improve containment.

The answer needs evidence that the change worked. Repeating that decision across the estate gives me a path I can revisit and explain, with fewer persistent credentials and a clearer understanding of the authority that remains.
