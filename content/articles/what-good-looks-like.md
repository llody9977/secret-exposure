## Good is a set of demonstrated capabilities

A well-controlled organisation can explain where important credentials come from, which workloads use them, what authority they carry, and how that authority can be stopped. It also knows where that explanation is incomplete.

A clean scan is useful evidence about a defined scan. It is not evidence that every credential is safe, that every exposure surface is covered, or that a response will succeed. Assess those capabilities separately.

## Ownership and inventory are dependable

For each critical service, credential metadata resolves to an accountable owner and an operational escalation route. The inventory is updated when an integration is created, changed, or retired. It contains no raw credential values and has its own access controls.

Test this by selecting a service from the business inventory, not only from the scanner's onboarded list. Trace its build, runtime, and vendor identities. Unmapped credentials and unknown owners should become findings with follow-up, not exclusions introduced to improve the result.

## Access is bounded and separation is real

A workload has only the authority needed for its purpose. Production and non-production identities are separated. Shared credentials are being removed or have a documented constraint and containment plan. Time limits reduce the duration of access where supported.

Evidence includes a deployed policy review and an authorised negative test: an identity intended for one service cannot access another. Verify the effective permissions, including inherited roles and trust relationships. Reading the intended policy is less persuasive if another policy grants broader access.

## Prevention and detection have known boundaries

New exposure is blocked where the chosen control supports it. Bypasses are visible and reviewed. Detection covers an agreed set of repositories and other surfaces, and failures to collect or scan are distinguishable from successful clean results.

Use synthetic fixtures representing the expected formats and file paths. Include negative examples to observe noise. A missing fixture should fail the evaluation, while an unsupported surface should appear as a coverage gap. Do not turn a small successful test into a claim that all unknown formats will be detected.

## Response works under service conditions

The operational team can invalidate exposed access, replace it safely, and confirm the old access no longer works. The procedure accounts for scheduled jobs, cached credentials, active sessions, and the possibility of continued issuance. Recovery has a named owner.

An exercise should include a realistic obstacle: the primary contact is unavailable, the provider console is inaccessible, or a consumer does not reload the replacement. Use isolated resources and agreed safety limits. The result should identify an operational improvement, not merely demonstrate that participants can read a runbook.

## Governance produces decisions and follow-through

Leaders see unresolved critical exposures, overdue exceptions, coverage gaps, and recurring causes. They can trace headline measures to evidence and understand the denominator. Decisions result in funded work or explicit acceptance by the right owner.

A useful test is to choose one repeated exposure route and follow it across several reporting periods. If the same cause persists without a decision, the reporting process may be functioning while governance is not producing the required change.

## Use a capability profile without averaging away gaps

For each dimension—ownership, access design, prevention, detection, response, and governance—record one of four evidence states: **unknown**, **defined**, **operating**, or **demonstrated**. Unknown means evidence is missing. Defined means the procedure and owner exist. Operating means recent records show it is used. Demonstrated means a relevant exercise or independent check supports the claimed outcome.

This is a proposed assessment aid for this series, not an industry maturity standard. Record the scope and date beside each judgement. Do not average the dimensions into a single score: excellent inventory does not compensate for an inability to revoke production access.

An illustrative service might have demonstrated ownership and operating detection but only a defined recovery procedure. Its next action is to test recovery and address the failures, not to buy another scanner to raise an aggregate score.

## Accept evidence with an expiry

A successful exercise proves something about the configuration and dependencies tested at that time. Reassess after material changes to identity, infrastructure, suppliers, or the application. Set periodic reviews based on criticality and change frequency.

Good does not mean exposure becomes impossible. It means the organisation can show that avoidable routes are reduced, remaining authority is bounded, and response works—and can identify where those claims stop being supported.
