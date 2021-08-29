
from datetime import timedelta, datetime

from flask import Flask
import prefect
from prefect.schedules import IntervalSchedule
from prefect import task, Flow

from db.database import init_db
from env_vars import prefect_project_name
from ingest.nvd_cve_data_ingest import ensure_cve_modified_feed_is_updated


schedule = IntervalSchedule(
    start_date=datetime.utcnow() + timedelta(hours=12),
    interval=timedelta(hours=12),
)

@task
def update_task():
    app = Flask(__name__)
    init_db(app)
    with app.app_context():
        logger = prefect.context.get("logger")
        logger.info("Checking for updates and writing any new records.")
        ensure_cve_modified_feed_is_updated()

def register_update_flow():
    flow = Flow("update_task", tasks=[update_task])
        
    flow.register(project_name=prefect_project_name)