#!/bin/sh
# Runs once, when the PostgreSQL image initialises an empty data directory (ADR 0022).
# Creates the login the API uses, bastion_app: not the owner of anything, no BYPASSRLS, so
# row-level security binds it. The migration job (owner) then grants it rows, not schema.
# The password comes from POSTGRES_APP_PASSWORD (gen-secrets); psql quotes it (:'pw'),
# nothing is spliced into SQL by the shell.
set -eu
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is missing}"
psql -v ON_ERROR_STOP=1 -v pw="$POSTGRES_APP_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE bastion_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'pw';
SQL
