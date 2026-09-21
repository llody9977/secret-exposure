# Credential lifecycle laboratory

This local Docker Compose laboratory demonstrates how a controlled credential exposure can move from intake and provisioning through detection, containment, recovery, and evidence collection.

It includes three application patterns:

- **Static credential:** Vault rotates a dedicated database credential, the application restarts, and the old password is rejected.
- **Dynamic credential:** Vault issues a short-lived database credential. The application renews or replaces its connection, and containment stops new issuance and active sessions.
- **Workload identity:** SPIRE issues an identity to a caller and protected service. Mutual TLS and target authorization permit the expected request and deny the wrong identity.

The lab uses disposable local data. It demonstrates one controlled path only. It is not a production deployment, a scanner benchmark, or evidence that every credential and exposure surface is covered.

## Run locally

From this directory, confirm the prerequisites and start the lab:

```bash
make doctor
make bootstrap
make up
```

Open [http://localhost:8000/](http://localhost:8000/). Choose one of the local demonstration roles from the role picker. The browser receives a short-lived session token; no password is displayed or entered.

Run the complete local acceptance flow with:

```bash
make test
```

The command exercises A01–A26 and writes a timestamped evidence package under `poc/evidence/`. Run `make browser-setup` once before testing on a machine without the browser-test dependency. Use `make down` to stop the lab and `make reset` to remove only this lab’s containers, volumes, and generated local secrets.

## Useful demonstrations

```bash
make demo-legacy
make demo-integrated
make demo-identity
```

These run the static credential, dynamic credential, and workload-identity demonstrations independently.

## Scope and technical contract

[Requirements](REQUIREMENTS.md) records the implemented security and operational contract. [Acceptance scenarios](ACCEPTANCE.md) records the observable checks and evidence format. The POC makes no external-adapter claim.
