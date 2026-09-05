.PHONY: check test lint format lock security docker-smoke

check: lint test

test:
	uv run coverage run -m unittest discover -s tests -v
	uv run coverage report --fail-under=90

security:
	uv run pip-audit --requirement requirements.lock --disable-pip

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff check --fix src tests
	uv run ruff format src tests

lock:
	uv lock
	uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
	uv export --frozen --only-group build --no-emit-project --format requirements-txt --output-file build-requirements.lock

docker-smoke:
	docker build -t mergegrounds-verifier:local .
	docker run --rm mergegrounds-verifier:local --version
