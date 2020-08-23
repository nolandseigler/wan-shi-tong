import os
from config import project_root

_ = project_root

db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASSWORD"]
db_name = os.environ["DB_NAME"]
db_host = os.environ["DB_HOST"]
db_port = os.environ["DB_PORT"]


db_uri = f"postgresql+pg8000://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"