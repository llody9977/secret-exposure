## Obtaining a value is only part of obtaining access

A credential found in a repository becomes useful to an adversary when the target still accepts it and the surrounding conditions permit access. The permissions behind the value, its lifetime, and any additional restrictions determine what can happen next.

This makes the exposure path worth separating from the access path. A public file may be readable without any prior foothold. A private build log may require access to the delivery platform. Runtime memory may require code execution beside the workload. These situations share a possible credential outcome but have different prerequisites and different opportunities for prevention.

MITRE ATT&CK groups several ways of obtaining unsecured credentials, including credentials in files and cloud instance metadata. The classification helps organize the mechanisms. It does not establish how often each occurs in a particular organization. [MITRE ATT&CK](https://attack.mitre.org/techniques/T1552/).

## The route through the environment matters

A secret can travel through source history, build configuration, logs, support attachments, and runtime processes. Each copy can acquire a different audience. Keeping the original in a secret manager does not determine who can read a later diagnostic dump.

The March 2025 compromise of `tj-actions/changed-files` demonstrated extraction of runner secrets into workflow logs. Public logs could expose those values beyond the execution environment. Use of the action alone does not establish that every repository lost a usable credential. [GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

The defensive implication is specific. Reviewing source for embedded credentials does not address every way code running with legitimate access can release them. Execution boundaries, privileges, log access, and response capability need to be considered together.

## Enrichment determines what a finding means

A detected string does not necessarily identify its issuer, consumer, owner, or effective authority. Those relationships need to be resolved against records established during intake and maintained through issuance and replacement.

Validity testing contributes one observation. An active credential may present an immediate containment concern. An invalid result does not establish whether the credential worked earlier, and an unavailable check does not establish invalidity. Target logs and investigation remain necessary to assess actual use.

Unknown ownership also needs an explicit response. A finding that cannot be correlated should reach a fallback team with its uncertainty intact. Guessing from a repository name can send the case to someone who lacks either knowledge or authority to act.

## A useful exercise follows one route to containment

A controlled local exercise can generate a disposable credential, expose it in a restricted fixture, detect it, and follow the resulting case to its owner. The test should establish whether the original access becomes ineffective and the application recovers.

The fixture must be clearly distinguished from a real incident and from a benchmark. A custom detector for the lab format proves that the integration path works for that format. It does not establish general discovery performance.

The [local POC](https://github.com/llody9977/secret_exposure/blob/main/poc/README.md) implements this controlled exercise and records its scenario evidence. It demonstrates one declared route from a disposable fixture to containment and recovery. It does not measure general scanner performance or establish that every credential type and exposure surface is covered.
