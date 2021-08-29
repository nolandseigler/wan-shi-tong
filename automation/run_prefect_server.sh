#! /usr/bin/env bash
# Step 1 of 3 in Prefect Start
# Config prefect for local server
poetry run prefect backend server

# Run local server(docker-compose services)
poetry run prefect server start
