PRODUCTION_ENV ?= deploy/digitalocean/production.env
PRODUCTION_COMPOSE = docker compose --env-file $(PRODUCTION_ENV) -f deploy/digitalocean/compose.yml

.PHONY: install install-security test test-integration check security web-check resilience-site production-validate production-build up down

install:
	python -m pip install -e '.[dev]'

install-security:
	python -m pip install -e '.[dev,security]'

test:
	python -m pytest tests --ignore=tests/integration

test-integration:
	python -m pytest tests/integration

check:
	python -m compileall -q bantam scripts security tests
	python -m ruff check bantam scripts security tests
	python -m ruff format --check bantam scripts security tests

security:
	python -m bandit -c pyproject.toml -r bantam scripts security
	python -m pip_audit --strict .
	semgrep --config .semgrep.yml --error --metrics=off bantam scripts security web/src

web-check:
	npm --prefix web audit --audit-level=high
	npm --prefix web run build

resilience-site:
	python -m scripts.resilience_report build --root . --output _site --commit local

production-validate:
	./deploy/digitalocean/validate-deployment.sh $(PRODUCTION_ENV)

production-build:
	$(PRODUCTION_COMPOSE) build

up:
	$(PRODUCTION_COMPOSE) up -d

down:
	$(PRODUCTION_COMPOSE) down
