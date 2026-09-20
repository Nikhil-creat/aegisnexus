.PHONY: up down logs test demo-data

up:            ## build + start everything on http://localhost:8080
	docker compose up --build -d
down:
	docker compose down
logs:
	docker compose logs -f
test:          ## run the test-suite locally (no torch needed)
	cd backend && pip install -r requirements-ci.txt && python -m pytest -q
demo-data:     ## regenerate docs/data/* using the trained CNNs inside Docker
	docker compose run --rm --no-deps --user "$$(id -u):$$(id -g)" -v "$$(pwd)/docs/data:/out" api python -m app.export_demo --out /out
