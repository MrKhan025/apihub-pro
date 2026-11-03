.PHONY: install test migrate seed audit run docker-up k8s-deploy

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements-dev.txt

migrate:
	PYTHONPATH=. python3 main.py migrate

seed:
	PYTHONPATH=. python3 main.py seed-demo

test:
	PYTHONPATH=. python3 -m unittest discover -s tests -v

audit:
	PYTHONPATH=. python3 main.py security-audit

run:
	PYTHONPATH=. python3 main.py serve --host 0.0.0.0 --port 8000

docker-up:
	docker compose --profile production up -d --build

k8s-deploy:
	kubectl apply -f deploy/k8s/
