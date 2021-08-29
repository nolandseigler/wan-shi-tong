from time import sleep

from flask import Flask

from db.database import init_db
from ingest.ensure_project_exists import ensure_project_exists
from ingest.flows.init_flow import register_init_flow
from ingest.flows.update_flow import register_update_flow

if __name__ == "__main__":
    ensure_project_exists()
    # make sure db has tables
    init_db()
    sleep(2)
    register_init_flow()
    register_update_flow()
