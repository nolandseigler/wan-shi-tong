#! /usr/bin/env bash
# Step 3 of 3 in Prefect Start
PROJECT_ROOT=$(git rev-parse --show-toplevel)

cd $PROJECT_ROOT

poetry run python "${PROJECT_ROOT}/ingest/register_flows.py"
