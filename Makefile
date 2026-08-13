.PHONY: bootstrap validate test lint

bootstrap:
	./scripts/bootstrap.sh

validate:
	./scripts/validate.sh

test:
	./scripts/test.sh

lint: validate
