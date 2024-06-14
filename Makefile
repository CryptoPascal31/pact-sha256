PACT := pact

all:
	tests

sha256-msg-tests.repl:
	python3 gen_sha256_tests.py > sha256-msg-tests.repl

tests: sha256-check-types.repl sha256-gas-tests.repl sha256-msg-tests.repl
	${PACT} sha256-check-types.repl
	@echo ""
	${PACT} sha256-gas-tests.repl
	@echo ""
	${PACT} sha256-msg-tests.repl
