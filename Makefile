.PHONY: build up down logs ps prod restart shell db-shell

# Development (auto-merges docker-compose.override.yml)
build:
	docker compose build

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f chronomancers_archives

ps:
	docker compose ps

restart:
	docker compose restart chronomancers_archives

shell:
	docker compose exec chronomancers_archives sh

db-shell:
	docker compose exec mysql sh -c 'MYSQL_PWD=$$MYSQL_PASSWORD mysql -u$$MYSQL_USER $$MYSQL_DATABASE'

# Production (no bind mount, secure cookies, resource limits)
prod:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
