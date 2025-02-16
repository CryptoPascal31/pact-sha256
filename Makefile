PACT := pact -t

POST := | grep "FAILURE" || true

all: tests

sha256-msg-tests.repl:
	python3 gen_sha256_tests.py > sha256-msg-tests.repl

sha256-mc-tests.repl:
	python3 gen_sha256_mc_tests.py > sha256-mc-tests.repl

test-msg: sha256-msg-tests.repl
	${PACT} sha256-msg-tests.repl ${POST}
	@echo ""

test-gas:
	${PACT} sha256-gas-tests.repl |grep "GAS:"
	@echo ""

test-mc: sha256-mc-tests.repl
	${PACT} sha256-mc-tests.repl | grep "CP:"


tests: test-gas test-msg test-mc

clean:
	rm -f sha256-msg-tests.repl sha256-mc-tests.repl
