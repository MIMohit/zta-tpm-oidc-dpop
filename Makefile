# Makefile - Root orchestration delegating to testbed and scripts
.PHONY: all testbed fleet-up fleet-down fleet-status attacks ablation rv lint test

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
	node scripts/attack-e1.mjs

ablation:
	node scripts/print-ablation.mjs 2>/dev/null || echo "Ablation framework target"

rv:
	$(MAKE) -C testbed rv

lint:
	$(MAKE) -C testbed lint

test:
	npm test
