PACT := pact

all: tests

sha256-msg-tests.repl:
	python3 gen_sha256_tests.py > sha256-msg-tests.repl

test-msg: sha256-msg-tests.repl
	${PACT} sha256-msg-tests.repl
	@echo ""

test-gas:
	${PACT} sha256-gas-tests.repl
	@echo ""

check-types:
	${PACT} sha256-check-types.repl
	 @echo ""

test-mc:
	${PACT} sha256-mc-tests.repl


tests: test-gas check-types test-msg test-mc
