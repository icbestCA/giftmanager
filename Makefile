PYBABEL := .venv/bin/pybabel
TRANSLATIONS := src/translations
LANGUAGES := es fr nl sv
NPM := npm --prefix frontend

.PHONY: run frontend frontend-install update-po compile-mo

run:
	docker compose -f docker-compose.dev.yml up --build

# Install frontend (Tailwind) dependencies
frontend-install:
	$(NPM) install

# Rebuild the Tailwind CSS bundle into src/static/css/app.css
frontend:
	$(NPM) run build

# Rebuild the Tailwind CSS bundle and watch for changes
frontend-watch:
	$(NPM) run watch

# Extract new strings from source and refresh all .po files
update-po:
	$(PYBABEL) extract -F babel.cfg -o $(TRANSLATIONS)/messages.pot src
	for lang in $(LANGUAGES); do \
		$(PYBABEL) update -i $(TRANSLATIONS)/messages.pot -d $(TRANSLATIONS) -l $$lang --previous; \
	done
	rm -f $(TRANSLATIONS)/messages.pot

# Compile all .po files into .mo binaries
compile-mo:
	$(PYBABEL) compile -d $(TRANSLATIONS)
