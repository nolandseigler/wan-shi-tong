from flask import Flask
import prefect
from prefect import task, Flow

from env_vars import prefect_project_name
from ingest.nvd_cve_data_ingest import download_and_hydrate_cve

@task
def init_task():
    app = Flask(__name__)
    with app.app_context():
        logger = prefect.context.get("logger")
        logger.info("Beginning full download and initial hydration. This will take quite awhile.")
        download_and_hydrate_cve()

def register_init_flow():
    
    flow = Flow("init_task", tasks=[init_task])
        
    flow.register(project_name=prefect_project_name, idempotency_key=flow.serialized_hash())