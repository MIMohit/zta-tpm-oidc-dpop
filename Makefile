# Makefile - Root orchestration delegating to testbed and scripts
.PHONY: all testbed fleet-up fleet-down fleet-status attacks ablation rv lint test figures fuzz e6 formal

all: testbed

testbed:
	$(MAKE) -C testbed testbed

fleet-up:
	$(MAKE) -C testbed fleet-up

fleet-down:
	$(MAKE) -C testbed fleet-down

fleet-status:
	$(MAKE) -C testbed fleet-status

attacks:
	node scripts/attacks/run.mjs --attacks all --config full --tpm swtpm

ablation:
	scripts/run-e1-final.sh

fuzz:
	node scripts/fuzz/fuzz.mjs --iters 200000 --seed 20261023 --out results/fuzz/latest

e6:
	for s in 1 2 3 4 5; do node bench/risk/simulate.mjs --users 1000 --days 37 --seed $$s --out results/e6-risk; done

# Figures need: python3 -m venv .venv-figures && .venv-figures/bin/pip install -r paper-figures/requirements.txt
FIGPY ?= .venv-figures/bin/python
E1 ?= $(lastword $(sort $(wildcard results/e1-final/*/inproc-swtpm/attacks.jsonl)))
E1_LIVE ?= $(lastword $(sort $(wildcard results/e1-final/*/live-tls/attacks-merged.jsonl)))
BENCH ?= $(lastword $(sort $(wildcard results/e1-final/*/bench-tls/)))
BENCH_NOTLS ?= $(lastword $(sort $(wildcard results/e1-final/*/bench/)))
# Every figure and table as PNG (300 dpi), PDF, SVG and HTML, plus paper-figures/out/index.html.
# Diagrams and HTML tables are rendered with headless Chrome ($CHROME or the default install).
formal:
	python3 formal/run.py

figures:
	$(FIGPY) paper-figures/make_figures.py --diagrams --e1 "$(E1)" --e1-label "in-process, real swtpm" --real-world --fleet results/fleet-check --formal formal/results/results.json \
	  --e6 results/e6-risk --fuzz results/fuzz/20261023 --fuzz results/fuzz/20261023-fixed \
	  $(if $(E1_LIVE),--e1-live "$(E1_LIVE)") $(if $(BENCH),--bench "$(BENCH)") $(if $(BENCH_NOTLS),--bench-notls "$(BENCH_NOTLS)")

rv:
	$(MAKE) -C testbed rv

lint:
	$(MAKE) -C testbed lint

test:
	npm test
