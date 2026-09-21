# Secret Exposure

[![Article validation](https://github.com/llody9977/secret_exposure/actions/workflows/publish.yml/badge.svg)](https://github.com/llody9977/secret_exposure/actions/workflows/publish.yml)
[![POC validation](https://github.com/llody9977/secret_exposure/actions/workflows/poc-ci.yml/badge.svg)](https://github.com/llody9977/secret_exposure/actions/workflows/poc-ci.yml)
[![Published guide](https://img.shields.io/badge/guide-GitHub%20Pages-222?logo=github)](https://llody9977.github.io/secret_exposure/)
[![License](https://img.shields.io/github/license/llody9977/secret_exposure)](LICENSE)

Secret Exposure is a practical guide to reducing the risk created when credentials reach the wrong place. It connects business impact, access design, detection, response, recovery, and governance.

Read the published guide at [llody9977.github.io/secret_exposure](https://llody9977.github.io/secret_exposure/).

## Articles

- [Why secret exposure matters to the business](content/articles/business-risk.md)
- [Where to start and who needs to own it](content/articles/action-plan.md)
- [Designing for the moment a credential escapes](content/articles/security-architecture.md)
- [Why good practices become difficult to implement](content/articles/implementation.md)
- [Responding when a secret is exposed](content/articles/incident-response.md)
- [Giving GRC a clear view of credential risk](content/articles/governance.md)
- [Recognizing good control through evidence](content/articles/what-good-looks-like.md)
- [Moving towards fewer persistent credentials](content/articles/path-forward.md)
- [How exposed credentials become usable access](content/articles/attacker-access-paths.md)
- [What secret scanners detect and where coverage stops](content/articles/scanner-capabilities.md)
- [Choosing a scanner against actual requirements](content/articles/choosing-a-scanner.md)
- [Connecting detection to a working response](content/articles/pipeline-lifecycle.md)
- [Replacing persistent credentials with workload identity](content/articles/workload-identity-lab.md)

## Local credential-lifecycle lab

The repository also includes a local Docker Compose demonstration of intake, detection, containment, recovery, and evidence collection. It uses Vault, PostgreSQL, and SPIRE across static credentials, dynamic credentials, and workload identity.

The lab demonstrates one controlled path with disposable credentials. It is not a production deployment, a scanner benchmark, or evidence that every credential type and exposure surface is covered. See the [local lab guide](poc/README.md) to run it.

## Contributing

Propose corrections with a primary source where applicable. Do not submit secrets, internal incident data, or confidential documents.

## License

Licensed under [Apache-2.0](LICENSE). This license covers the repository's code and written material.
