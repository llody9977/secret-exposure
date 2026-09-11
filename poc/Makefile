.PHONY: all doctor bootstrap up demo-legacy demo-integrated demo-identity test evidence down reset help

COMPOSE_FILE ?= docker-compose.yml
PROJECT_NAME ?= poc
BASE_IMAGE ?= poc-lab-base:latest
PYTHON ?= $(shell if [ -x /tmp/secret-exposure-check-venv/bin/python ]; then echo /tmp/secret-exposure-check-venv/bin/python; elif [ -f .venv/bin/python3 ]; then echo .venv/bin/python3; elif [ -f poc/.venv/bin/python3 ]; then echo poc/.venv/bin/python3; else echo python3; fi)

all: doctor build up

build: build-image build-bins

build-image:
	docker build -f Dockerfile.base -t $(BASE_IMAGE) .

build-bins:
	@echo "Building Linux SPIFFE binaries for the Docker engine architecture..."
	@mkdir -p apps/spiffe/bin
	@docker run --rm -v "$$(pwd)/apps/spiffe:/src" -w /src golang:1.24.6-bookworm sh -ec 'CGO_ENABLED=0 GOOS=linux go build -mod=readonly -o bin/spiffe-caller ./caller; CGO_ENABLED=0 GOOS=linux go build -mod=readonly -o bin/spiffe-service ./service'

browser-setup:
	@$(PYTHON) -m pip install playwright==1.51.0
	@$(PYTHON) -m playwright install chromium

unit-test:
	@docker run --rm --network none -v "$$(pwd):/poc:ro" -w /poc poc-lab-base:latest python3 -m unittest discover -s tests -v

# Per-deployment random credentials (GitLab root password, supervisor/HMAC secrets).
# docker compose auto-loads this file; it is git-ignored and recreated by 'make reset'.
.env:
	@$(PYTHON) scripts/bootstrap.py --gen-env

help:
	@echo "Credential Lifecycle Laboratory (POC)"
	@echo "Available make targets:"
	@echo "  make doctor           - Check environment, tools, resources, and files"
	@echo "  make bootstrap        - Generate TLS certs, init Vault, seed DB and AppRoles"
	@echo "  make up               - Start all lab containers via Docker Compose"
	@echo "  make demo-legacy      - Run legacy app exposure, rotation, and restart demo"
	@echo "  make demo-integrated  - Run dynamic credential issuance, renewal, and revocation demo"
	@echo "  make demo-identity    - Run SPIFFE workload attestation, mTLS, and policy deny demo"
	@echo "  make test             - Run full A01-A26 acceptance test suite and generate report"
	@echo "  make evidence         - Export evidence package to evidence/<run_id>/"
	@echo "  make down             - Stop all lab containers"
	@echo "  make reset            - Confined project cleanup (requires CONFIRM=yes or prompt)"

doctor:
	@$(PYTHON) scripts/doctor.py

bootstrap: build .env
	@./certs/generate_certs.sh
	@docker compose -p $(PROJECT_NAME) -f $(COMPOSE_FILE) up -d postgres vault spire-server lab-ingress
	@$(PYTHON) scripts/bootstrap.py

up: .env
	@docker compose -p $(PROJECT_NAME) -f $(COMPOSE_FILE) up -d
	@$(PYTHON) scripts/bootstrap.py --seed-only

up-gitlab: .env
	@docker compose -p $(PROJECT_NAME) -f $(COMPOSE_FILE) --profile gitlab up -d
	@$(PYTHON) scripts/bootstrap.py --seed-only
	@$(PYTHON) scripts/gitlab_setup.py

demo-legacy:
	@$(PYTHON) scripts/run_scenarios.py --scenario A06

demo-integrated:
	@$(PYTHON) scripts/run_scenarios.py --scenario A09,A10

demo-identity:
	@$(PYTHON) scripts/run_scenarios.py --scenario A12,A14

test:
	@$(PYTHON) scripts/run_scenarios.py --all

evidence:
	@$(PYTHON) scripts/export_evidence.py

down:
	@docker compose -p $(PROJECT_NAME) -f $(COMPOSE_FILE) down

reset:
	@echo "Confined project reset requested."
	@if [ "$$CONFIRM" != "yes" ]; then \
		echo "Warning: This will remove volumes and bootstrap data for this lab project only."; \
		read -p "Type 'yes' to proceed with reset: " answer; \
		if [ "$$answer" != "yes" ]; then echo "Reset aborted."; exit 1; fi; \
	fi
	@docker compose -p $(PROJECT_NAME) -f $(COMPOSE_FILE) down -v --remove-orphans
	@rm -rf .bootstrap/ .vault-data/ fixtures/ evidence/ .env
	@echo "Lab reset completed cleanly without affecting other Docker projects."
