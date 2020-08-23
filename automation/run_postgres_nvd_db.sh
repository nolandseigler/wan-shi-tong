#! /usr/local/bin/bash
# above assumes homebrew bash

ROOT=$(git rev-parse --show-toplevel)
cd $ROOT

set -o allexport

source .env-no-git

set +o allexport

[[ $DB_PORT ]] || { echo "'DB_PORT' must be set in .env-no-git"; exit 1; }
[[ $DB_USER ]] || { echo "'DB_USER' must be set in .env-no-git"; exit 1; }
[[ $DB_PASSWORD ]] || { echo "'DB_PASSWORD' must be set in .env-no-git"; exit 1; }
[[ $DB_NAME ]] || { echo "'DB_NAME' must be set in .env-no-git"; exit 1; }


docker container run -d -p "${DB_PORT}:5432" --name="postgres_${DB_NAME}" -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" postgres:12.4