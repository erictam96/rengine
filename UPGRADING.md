# Upgrading to reNgine v2.3

v2.3 moves reNgine to Django 5.2 LTS, which needs PostgreSQL 14 or newer. Existing installs run PostgreSQL 12, so the database has to be migrated **once**.

## Steps

```bash
cd rengine
make down
git pull
make upgrade-db   # dumps PostgreSQL 12 data and restores it into PostgreSQL 17
make build
make up
```

`make upgrade-db`:

1. stops the reNgine containers
2. starts a temporary PostgreSQL 12 container on your existing `rengine_postgres_data` volume and runs `pg_dumpall`
3. restores the dump into a new `rengine_postgres17_data` volume
4. keeps the SQL dump in `./backups/`

Your old volume is **not modified or deleted**. Once you've confirmed your targets and scans are there, remove it:

```bash
docker volume rm rengine_postgres_data
```

> If you skip `make upgrade-db`, reNgine starts with an empty PostgreSQL 17 database. Your data is still in the old volume, so just run `make down && make upgrade-db && make up`. If the new volume already holds data, the script refuses to overwrite it.

## Rollback

```bash
make down
git checkout v2.2.0
make build && make up
```

v2.2.0 uses the untouched `rengine_postgres_data` volume.

## New optional settings (`.env`)

| Variable | Purpose |
| --- | --- |
| `OLLAMA_INSTANCE` | URL of the Ollama server, e.g. a remote GPU host (default `http://ollama:11434`) |
| `OPENAI_BASE_URL` | Use an OpenAI-compatible server (LM Studio, vLLM, OpenRouter …) instead of api.openai.com |
| `NVD_API_KEY` | Raises the NVD rate limit for CVE enrichment |

The Anthropic (Claude) API key is set in **Settings → API Vault**, then pick a Claude model in **Settings → LLM Toolkit**.

## Notes

- The first `celery` start after upgrading re-clones theHarvester at 4.11.1 (your `api-keys.yaml` is kept) and builds per-tool virtualenvs, so it takes a few minutes.
- amass stays on v3.23.3. Moving to amass v5 needs a parser rewrite, which is planned separately.
