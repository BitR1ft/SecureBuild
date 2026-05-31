.PHONY: install run test lint scan dashboard report clean coverage

PYTHON ?= python3
PIP ?= pip3

install:
	$(PIP) install -r requirements.txt
	pre-commit install
	mkdir -p data logs reports

run:
	$(PYTHON) cli.py scan .

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	black . --check
	flake8 . --max-line-length=120
	isort . --check-only

scan:
	$(PYTHON) cli.py scan $(REPO) --verbose

dashboard:
	$(PYTHON) cli.py dashboard --port 5000

report:
	$(PYTHON) cli.py report $(RUN_ID) --format pdf

coverage:
	$(PYTHON) -m pytest tests/ --cov=. --cov-report=html --cov-report=term

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf htmlcov/ .coverage .pytest_cache/

generate-api-key:
	$(PYTHON) cli.py generate-api-key --name $(NAME)

docker-build:
	docker build -t securebuild:latest .

docker-run:
	docker run -v $(REPO):/scan securebuild:latest scan /scan

docker-dashboard:
	docker-compose up dashboard

docker-scan:
	docker run --rm -v $(REPO):/scan -v ./reports:/reports securebuild:latest scan /scan -o /reports

docker-push:
	docker tag securebuild:latest ghcr.io/$(USER)/securebuild:$(TAG)
	docker push ghcr.io/$(USER)/securebuild:$(TAG)

audit:
	$(PIP) audit
