# ╔══════════════════════════════════════════════════════════════╗
# ║               Sentinel-Core — Makefile                      ║
# ║  One-command orchestration for the eBPF security pipeline   ║
# ╚══════════════════════════════════════════════════════════════╝

.PHONY: help up down demo logs test forwarder install port-forward clean

SHELL := /bin/bash

# ── Defaults ──────────────────────────────────────────────────────
CLUSTER_NAME ?= sentinel-core
VENV_DIR     ?= .venv
PYTHON       ?= python3

help: ## Show this help
	@echo "Sentinel-Core — Makefile Targets"
	@echo "════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Infrastructure ────────────────────────────────────────────────

up: ## Create Kind cluster + install Tetragon + apply policies
	@chmod +x scripts/*.sh
	@bash scripts/setup-cluster.sh

down: ## Delete the Kind cluster
	@bash scripts/teardown.sh

port-forward: ## Port-forward Tetragon gRPC to localhost:54321
	kubectl -n kube-system port-forward svc/tetragon 54321:54321 &

# ── Python Environment ───────────────────────────────────────────

install: ## Install Python dependencies into a virtualenv
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install --upgrade pip
	$(VENV_DIR)/bin/pip install -r forwarder/requirements.txt
	@echo "✅ Run 'source $(VENV_DIR)/bin/activate' to activate the virtualenv."

# ── Event Forwarder ───────────────────────────────────────────────

forwarder: ## Start the event forwarder (live tetra mode)
	$(VENV_DIR)/bin/python -m forwarder.main

forwarder-offline: ## Start the forwarder in offline mode (sample data)
	$(VENV_DIR)/bin/python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl

# ── Demo ──────────────────────────────────────────────────────────

demo: ## Run the attack simulation demo
	@bash scripts/run-demo.sh

# ── Testing ───────────────────────────────────────────────────────

test: ## Run unit tests
	$(VENV_DIR)/bin/python -m pytest forwarder/tests/ -v --tb=short

test-quick: ## Run tests without virtualenv (uses system python)
	$(PYTHON) -m pytest forwarder/tests/ -v --tb=short

# ── Logs ──────────────────────────────────────────────────────────

logs: ## Tail Tetragon pod logs
	kubectl -n kube-system logs -l app.kubernetes.io/name=tetragon -f --tail=50

logs-events: ## Stream raw Tetragon events via tetra CLI
	tetra getevents -o compact --server-address localhost:54321

# ── Cleanup ───────────────────────────────────────────────────────

clean: ## Remove virtualenv and cached files
	rm -rf $(VENV_DIR) __pycache__ forwarder/__pycache__ forwarder/tests/__pycache__
	rm -rf .pytest_cache forwarder/.pytest_cache
	find . -name "*.pyc" -delete
