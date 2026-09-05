## I would look for capabilities I can demonstrate

When I ask what good looks like, I do not mean a dashboard with no findings. I mean being able to explain where important credentials come from, which workloads use them, what authority they carry, and how that authority can be stopped.

I also want to know where that explanation is incomplete. A clean scan is evidence about a defined scan. It cannot establish that every surface is covered or that recovery will succeed.

## I should be able to find the owner

For a critical service, I would expect credential metadata to lead to an accountable owner and a reachable operational contact. The inventory needs to change when an integration is created, altered, or retired. It should not become another store of raw secrets.

To test this, I would select a service from the business inventory rather than only from the scanner's onboarded list. I would follow its build, runtime, and supplier identities. An unmapped credential should produce follow up work rather than a convenient exclusion from the assessment.

## The access boundary should hold in practice

I would expect a workload's authority to fit its purpose and production identities to be separate from development identities. Shared credentials should either be removed or have a specific constraint and containment plan.

The evidence I would find persuasive includes an authorised negative test (i.e. showing that an identity intended for one service cannot access another). I would examine effective permissions, including inherited roles and trust relationships. The intended policy is not enough if another policy grants broader access.

## I should understand what the controls can miss

I would want new exposure blocked where the preventive control supports it, with bypasses visible and reviewed. Detection should cover an agreed set of surfaces, and a failure to collect or scan should be distinguishable from a clean result.

I would use synthetic fixtures representing expected formats and paths, together with examples that should not trigger findings. A missed expected fixture tells me something needs attention. An unsupported surface tells me there is a coverage gap.

What I would avoid is turning a small successful evaluation into a claim that unknown formats will also be detected. The result needs to keep the boundary of the exercise attached to it.

## Recovery should work under service conditions

I would want the operational team to demonstrate that exposed access can be invalidated, replacement access works, and the old access fails. The procedure needs to account for scheduled jobs, caches, sessions, and continued issuance.

An exercise becomes more useful when it includes a realistic obstacle (e.g. the primary contact is unavailable or a consumer does not reload its configuration). I would use isolated resources and agreed safety limits. The purpose is to find an operational weakness before a real response depends on it.

## Reporting should produce action

I would want leaders to see unresolved critical exposures, overdue exceptions, coverage gaps, and recurring causes. They should be able to trace the headline measures to evidence and understand what has been left out.

One check I would make is to follow a repeated exposure route across several reporting periods. If nothing changes and no accountable decision is made, the reporting may be functioning without producing the governance outcome I need.

## A capability profile helps me keep the gaps separate

For my own recap, I would record ownership, access design, prevention, detection, response, and governance separately. I would describe each as unknown, defined, operating, or demonstrated.

Unknown means evidence is missing. Defined means an owner and procedure exist. Operating means recent records show the procedure is used. Demonstrated means a relevant exercise or independent check supports the claimed outcome.

This is a proposed assessment aid, not an industry maturity standard. I would record its scope and date and avoid averaging the dimensions. Strong inventory cannot compensate for an inability to revoke production access.

An imagined service with demonstrated ownership but only a written recovery procedure gives me a clear next action. I would exercise recovery rather than buy another scanner to improve an overall score.

## I need to revisit evidence after change

A successful exercise supports a conclusion about the configuration tested at that time. Changes to identity, infrastructure, suppliers, or the application can weaken that conclusion.

I would reassess after material changes and set periodic reviews that reflect criticality and change frequency. What I want to retain is a clear account of the capabilities demonstrated, the conditions they depend on, and the gaps I still need to address.
