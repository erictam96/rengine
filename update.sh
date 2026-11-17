#!/bin/bash

# Since v2.3.0 reNgine runs on PostgreSQL 17 (Django 5.2 needs >= 14).
# Migrate the legacy PostgreSQL 12 volume once, after pulling and before starting.
migrate_db_if_needed() {
  local project
  project=$(grep -E '^COMPOSE_PROJECT_NAME=' .env | cut -d= -f2)
  project=${project:-rengine}
  if docker volume inspect "${project}_postgres_data" >/dev/null 2>&1 && \
     ! docker volume inspect "${project}_postgres17_data" >/dev/null 2>&1; then
    echo "Legacy PostgreSQL 12 data found, migrating to PostgreSQL 17..."
    ./scripts/upgrade_postgres.sh || { echo "Database migration failed, aborting update."; exit 1; }
  fi
}

echo "Do you want to apply your local changes after updating? (y/n)"
read answer
answer=$(echo $answer | tr '[:upper:]' '[:lower:]')

if [[ $answer == "y" ]]; then
  make down && git stash save && git pull && git stash apply && migrate_db_if_needed && make build && make up
elif [[ $answer == "n" ]]; then
  make down && git stash && git stash drop && git pull && migrate_db_if_needed && make build && make up
else
  echo "Invalid input. Please enter 'y' or 'n'."
fi
