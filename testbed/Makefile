# testbed/Makefile - Testbed lifecycle and automation targets
.PHONY: testbed fleet-up fleet-down fleet-status ca manufacture images rv lint dry-run clean

testbed: ca manufacture

fleet-up:
	./fleet.sh up

fleet-down:
	./fleet.sh down

fleet-status:
	./fleet.sh status

ca:
	./ca-init.sh good
	./ca-init.sh foreign

manufacture: ca
	./manufacture.sh dev-good --ca good --profile p384
	./manufacture.sh dev-tampered --ca good --profile p384
	./manufacture.sh dev-rogue --ca good --profile p384
	./manufacture.sh dev-foreign --ca foreign --profile p384

images:
	./image-fetch.sh
	./image-build.sh golden
	./image-build.sh tampered

rv:
	./rv-capture.sh

lint:
	bash tests/lint.sh

dry-run:
	bash tests/dry-run.sh

clean:
	rm -rf state/ ca/ images/
