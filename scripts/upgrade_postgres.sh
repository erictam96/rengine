#!/usr/bin/env bash
# Migrate reNgine data from the legacy PostgreSQL 12 volume to PostgreSQL 17.
#
# Django 5.2 requires PostgreSQL >= 14, so installs from reNgine <= 2.2.x
# must move their data once. The old volume is left untouched, so you can
# roll back by checking out the previous release.
#
# Usage: ./scripts/upgrade_postgres.sh      (or: make upgrade-db)
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
set -a; source .env; set +a

PROJECT=${COMPOSE_PROJECT_NAME:-rengine}
OLD_VOL="${PROJECT}_postgres_data"
NEW_VOL="${PROJECT}_postgres17_data"
DUMP_DIR="$(pwd)/backups"
DUMP_FILE="${DUMP_DIR}/rengine_pg12_$(date +%Y%m%d_%H%M%S).sql"

if ! docker volume inspect "$OLD_VOL" >/dev/null 2>&1; then
  echo "No legacy volume $OLD_VOL found - nothing to migrate."
  exit 0
fi

if docker volume inspect "$NEW_VOL" >/dev/null 2>&1; then
  count=$(docker run --rm -v "$NEW_VOL":/data alpine sh -c 'ls -A /data | wc -l')
  if [ "$count" != "0" ]; then
    echo "Target volume $NEW_VOL already contains data. Aborting to avoid overwriting it."
    echo "Remove it first (docker volume rm $NEW_VOL) if you want to redo the migration."
    exit 1
  fi
fi

echo "[1/5] Stopping reNgine services..."
docker compose stop web celery celery-beat db >/dev/null 2>&1 || true

mkdir -p "$DUMP_DIR"
echo "[2/5] Starting temporary PostgreSQL 12 on $OLD_VOL..."
docker run -d --rm --name rengine_pg12_tmp \
  -e POSTGRES_USER="$POSTGRES_USER" -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" -e POSTGRES_DB="$POSTGRES_DB" \
  -v "$OLD_VOL":/var/lib/postgresql/data postgres:12-alpine >/dev/null
until docker exec rengine_pg12_tmp pg_isready -U "$POSTGRES_USER" >/dev/null 2>&1; do sleep 1; done

echo "[3/5] Dumping database to $DUMP_FILE ..."
docker exec rengine_pg12_tmp pg_dumpall -U "$POSTGRES_USER" > "$DUMP_FILE"
docker stop rengine_pg12_tmp >/dev/null

echo "[4/5] Restoring into PostgreSQL 17 volume $NEW_VOL ..."
docker volume create "$NEW_VOL" >/dev/null
docker run -d --rm --name rengine_pg17_tmp \
  -e POSTGRES_USER="$POSTGRES_USER" -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" -e POSTGRES_DB="$POSTGRES_DB" \
  -v "$NEW_VOL":/var/lib/postgresql/data -v "$DUMP_DIR":/backups:ro postgres:17-alpine >/dev/null
until docker exec rengine_pg17_tmp pg_isready -U "$POSTGRES_USER" >/dev/null 2>&1; do sleep 1; done
sleep 2
docker exec rengine_pg17_tmp psql -q -U "$POSTGRES_USER" -d postgres -f "/backups/$(basename "$DUMP_FILE")" >/dev/null
docker stop rengine_pg17_tmp >/dev/null

echo "[5/5] Done. Start reNgine with: make up"
echo "Dump kept at $DUMP_FILE. The old volume $OLD_VOL is untouched; delete it once you've verified the upgrade:"
echo "  docker volume rm $OLD_VOL"
