PY ?= python3

.PHONY: help install lint validate test coverage convert events demo all clean

help:  ## Show this help
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

install:  ## Install dependencies
	$(PY) -m pip install -r requirements.txt

lint:  ## Lint and format-check the Python code
	ruff check .
	ruff format --check .

validate:  ## Quality gate + sigma check
	$(PY) -m scripts.validate_rules
	sigma check --fail-on-issues -x d3_fendtag detections

test:  ## Run all tests
	$(PY) -m pytest -v

coverage:  ## Regenerate docs/coverage.md and the ATT&CK Navigator layer
	$(PY) -m scripts.coverage_report

convert:  ## Convert rules to Splunk / Elastic / Sentinel queries in build/queries
	$(PY) -m scripts.convert_rules

events:  ## Regenerate samples/attack_simulation.jsonl
	$(PY) -m scripts.generate_events

demo:  ## Hunt over the simulated attack day
	$(PY) -m scripts.hunt samples/attack_simulation.jsonl

all: lint validate test convert demo  ## Run the full CI pipeline locally

clean:  ## Remove generated files
	rm -rf build .pytest_cache .ruff_cache