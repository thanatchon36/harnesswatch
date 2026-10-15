SHELL := /bin/bash
.DEFAULT_GOAL := check
UV ?= uv
RUN := $(UV) run

.PHONY: all check lint fmt types test cov build docs experiments bench bench-images paper clean

EXP := $(RUN) --group experiments python
BENCH_DIR ?= bench/results/2026-10-15
BENCH_N ?= 5

## all: lint -> type -> test -> docs -> experiments (offline, from committed results) -> paper -> build
all: lint types cov docs experiments paper build

check: lint types test

lint:
	$(RUN) ruff format --check .
	$(RUN) ruff check .

fmt:
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

types:
	$(RUN) mypy

test:
	$(RUN) pytest

cov:
	$(RUN) pytest --cov --cov-report=term --cov-report=xml --cov-fail-under=85

build:
	$(UV) build

## docs: generate reference pages, then build the MkDocs site (strict)
docs:
	$(RUN) python scripts/gen_docs.py
	$(RUN) --group docs mkdocs build --strict

## experiments: regenerate every results JSON-derived table and figure without network or Docker
experiments:
	$(EXP) experiments/rq3_incidents.py
	$(EXP) experiments/e1_matrix.py
	$(EXP) experiments/e3_bench.py $(BENCH_DIR)
	$(EXP) experiments/e5_table.py
	$(EXP) experiments/e2_strata.py
	$(EXP) experiments/e6_eval.py
	$(EXP) experiments/e7_claims.py
	$(EXP) experiments/e4_supply.py --tables-only
	$(EXP) experiments/e2_corpus.py --tables-only
	$(EXP) experiments/rules_table.py
	$(EXP) experiments/taxonomy_table.py
	$(EXP) experiments/paper_numbers.py
	$(RUN) python scripts/render_brief.py
	$(RUN) python scripts/gen_checklist_check.py --write

## bench-images: build the pinned harness images used by the canary-bench and observe
bench-images:
	docker build -t harnesswatch-bench-base:1 -f bench/docker/base.Dockerfile bench/docker
	docker build -t harnesswatch-bench-claude-code:2.1.300 -f bench/docker/harnesses/claude-code.Dockerfile bench/docker
	docker build -t harnesswatch-bench-grok-build:1.0.52 --build-arg PKG=@xai-official/grok@1.0.52 -f bench/docker/harnesses/npm.Dockerfile bench/docker
	docker build -t harnesswatch-bench-github-copilot:1.0.98 --build-arg PKG=@github/copilot@1.0.98 -f bench/docker/harnesses/npm.Dockerfile bench/docker
	docker build -t harnesswatch-bench-opencode:1.19.0 --build-arg PKG=opencode-ai@1.19.0 -f bench/docker/harnesses/npm.Dockerfile bench/docker
	docker build -t harnesswatch-bench-codex-cli:0.162.1 --build-arg PKG=@openai/codex@0.162.1 -f bench/docker/harnesses/npm.Dockerfile bench/docker
	docker build -t harnesswatch-bench-qwen-code:0.25.1 --build-arg PKG=@qwen-code/qwen-code@0.25.1 -f bench/docker/harnesses/npm.Dockerfile bench/docker
	docker build -t harnesswatch-bench-aider:0.86.2 -f bench/docker/harnesses/aider.Dockerfile bench/docker
	docker build -t harnesswatch-bench-antigravity:latest -f bench/docker/harnesses/antigravity.Dockerfile bench/docker

## bench: run (or resume) the canary-bench grid against the local Ollama model, then analyse it.
## Needs Docker, the bench images and an Ollama container reachable as `ollama` on hw-bench-net.
bench: bench-images
	$(RUN) harnesswatch bench run --out $(BENCH_DIR) --raw bench/.work/raw -n $(BENCH_N) --parallel 2 --timeout 240 --model qwen3:4b-instruct \
	  --scenario control --scenario readme --scenario instructions --scenario code_comment --scenario tool_output
	$(EXP) experiments/e3_bench.py $(BENCH_DIR)

## paper: build paper/main.pdf (pinned Tectonic) and the Markdown mirror
paper:
	bash paper/build.sh

clean:
	rm -rf dist build .coverage coverage.xml htmlcov site
