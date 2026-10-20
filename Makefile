# HydraX top-level Makefile
# Focused on the live lab harness (lab-up / lab-test / lab-down).

COMPOSE_FILE     = lab/docker-compose.yml
COMPOSE          = docker compose -f $(COMPOSE_FILE)
PYTEST_LIVE      = python -m pytest -m live tests_live/ -v --tb=short

# ---------------------------------------------------------------------------
# Hermetic (default) tests — no Docker required
# ---------------------------------------------------------------------------
test:
	python -m pytest -q

# ---------------------------------------------------------------------------
# Lab lifecycle
# ---------------------------------------------------------------------------

lab-up: ## Start the lab containers and seed initial state
	$(COMPOSE) up -d postgres hydrax-api connector victim
	@echo "Waiting for containers to stabilise..."
	@sleep 8
	python lab/seed.py

lab-attack: ## Run one batch of benign attack signals through the attacker container
	$(COMPOSE) run --rm attacker python /app/lab/attack_sim.py --once

lab-test: ## Run the live S1–S12 test suite against the running lab
	@mkdir -p evidence
	$(PYTEST_LIVE) 2>&1 | tee evidence/lab_run_$(shell date +%Y%m%d_%H%M%S).log

lab-teardown: ## Clear transient lab state (WAF rules, brain_actions) without stopping containers
	python lab/teardown.py

lab-down: ## Tear down transient state then stop and remove all lab containers and volumes
	-python lab/teardown.py
	$(COMPOSE) down -v

lab-logs: ## Stream logs from all lab containers
	$(COMPOSE) logs -f

benchmark: ## Run the FP/precision benchmark (skips unreachable targets gracefully)
	python benchmark/runner.py

.PHONY: test lab-up lab-attack lab-test lab-teardown lab-down lab-logs benchmark
