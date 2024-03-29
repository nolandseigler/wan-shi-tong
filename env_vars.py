import os
from config import project_root

cpe_data_dir = project_root / "cpe_data"
cve_data_dir = project_root / "cve_data"

db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASSWORD"]
db_name = os.environ["DB_NAME"]
db_host = os.environ["DB_HOST"]
# BE SURE THIS ISNT THE STANDARD PORT 5432
# PREFECT SERVER POSTGRES CONSUMES 5432
db_port = os.environ["DB_PORT"]


db_uri = f"postgresql+pg8000://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

prefect_project_name = "NVD INGEST"
