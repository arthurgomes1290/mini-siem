.PHONY: help build up down logs init-db version shell test clean demo

PKG := mini_siem

help:
	@echo "Comandos:"
	@echo "  make up        Sobe o container (build se necessário)"
	@echo "  make down      Derruba o container"
	@echo "  make logs      Mostra logs do container"
	@echo "  make version   Executa 'mini-siem version' dentro do container"
	@echo "  make init-db   Cria o schema no SQLite dentro do container"
	@echo "  make shell     Abre bash no container"
	@echo "  make test      Roda pytest no host"
	@echo "  make demo      Dispara 1 cenário por regra e lista alertas (local)"
	@echo "  make clean     Remove dados locais e caches"

.env:
	cp .env.example .env

build:
	docker compose build

up: .env
	docker compose up -d --build
	@echo "Container no ar. Rode 'make init-db' ou 'make shell'."

down:
	docker compose down

logs:
	docker compose logs -f

version: up
	docker compose exec siem python -m $(PKG) version

init-db: up
	docker compose exec siem python -m $(PKG) init-db

shell: up
	docker compose exec siem bash

test:
	python -m pytest

demo:
	./tools/demo.sh

clean:
	rm -rf data .pytest_cache
	find . -type d -name __pycache__ -not -path './_legacy/*' -exec rm -rf {} +
