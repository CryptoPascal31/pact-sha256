PACT := pact -t

POST := | grep "FAILURE" || true

all: tests

sha256-msg-tests.repl:
	python3 gen_sha256_tests.py > sha256-msg-tests.repl

test-msg: sha256-msg-tests.repl
	${PACT} sha256-msg-tests.repl ${POST}
	@echo ""

test-gas:
	${PACT} sha256-gas-tests.repl
	@echo ""


test-mc:
	${PACT} sha256-mc-tests.repl

tests: test-gas test-msg test-mc

