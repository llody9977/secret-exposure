## The difficult part is changing the dependency

Most teams understand the advice to avoid hardcoded secrets, limit access, and rotate credentials. Implementation becomes difficult when an old application, a vendor API, or a deployment process depends on the current arrangement. A workable programme changes those dependencies in an order the service can tolerate.

Treat each obstacle as an engineering constraint with an owner and an exit condition. Repeating the policy will not make a process reload configuration or give a supplier a revocation API.

## Noisy scanning: improve the decision quality

An initial history scan may produce years of findings, duplicates, examples, and credentials that are no longer valid. Route new exposures separately from the historical backlog so urgent work is not hidden by old noise. Deduplicate by a protected identifier without copying raw values into tickets or dashboards.

Use a representative evaluation set: the credential types your organisation uses, realistic non-secrets, known file formats, and the surfaces in scope. Record false positives and missed examples separately. A result on that set is evidence about that set; it is not a universal detection rate.

Push protection and background scanning have different coverage. GitHub documents differences in supported patterns and other detection limits. Confirm the protection available for each relevant secret type before making a prevention claim. [GitHub detection scope](https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope).

Do not suppress a whole directory merely because it is noisy. Narrow the exclusion, document the reason, and retain a test that would detect an accidental widening. A broad exception can convert an inconvenient control into an invisible gap.

## Fragile rotation: map consumers first

A shared database password may be used by the main application, a scheduled report, and an old recovery script. Updating only the main application can look successful until the next scheduled task fails. Map consumers through configuration, access logs, and owner interviews; no single source is guaranteed complete.

If the provider supports overlapping credentials, issue the replacement, update consumers, verify service health, then invalidate the old value within a controlled window. GitHub's remediation guidance describes this sequencing when downtime is a concern. It also leaves an exposure window while both values work, so active abuse may justify immediate revocation instead. [GitHub remediation guidance](https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret).

Where overlap is impossible, rehearse a coordinated cutover. Prepare a recovery path that does not restore a known exposed credential. Record which caches, sessions, and background jobs need separate treatment.

## Legacy systems: contain what cannot yet be removed

A supplier may support only one static key with broad permissions. Record that limitation and seek a narrower integration, but reduce risk now: isolate the calling service, restrict access to the stored key, monitor use, and apply provider-supported network restrictions where feasible. None of these compensating controls makes the key harmless.

An exception should state the remaining authority, the reason migration is blocked, the service owner accepting the risk, and the next decision date. Attach a concrete exit condition, such as a vendor upgrade or replacement interface. A recurring approval with no change in the dependency is evidence that the roadmap needs attention.

## Delivery pressure: make the supported route usable

If the approved method requires days of manual setup while a copied token works immediately, teams have a strong incentive to improvise. Provide a documented integration pattern, a development environment with non-production access, and a clear escalation route for blocked releases.

Pilot preventive blocking after the supported route works. Explain how to replace the credential and how to challenge an incorrect finding. For an urgent bypass, require a recorded reason and review appropriate to the risk. Review bypass patterns to find broken workflows, not only individual mistakes.

Keep examples free of live credentials. Use conspicuously synthetic placeholders, and ensure training does not teach staff to paste secrets into chat or debugging tools to resolve an alert.

## Roll out in two tracks

For new services, make the chosen identity and secret-management pattern part of the deployment template. For existing services, prioritise by authority, exposure opportunities, and recovery difficulty. High alert volume alone may point to repetition rather than the most consequential risk.

Expand after the pilot demonstrates that developers can use the control, responders can act on it, and the service can recover. Report unresolved dependencies alongside progress. That gives management a clear choice about the engineering work still required.
