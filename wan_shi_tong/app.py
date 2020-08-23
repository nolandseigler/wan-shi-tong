import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
from flask import Flask
import plotly.express as px
import pandas as pd

from db.database import init_db, db
from wan_shi_tong.dash_init import register_dash

app_name = __name__

def create_app(config_name: str):

    app = Flask(app_name, instance_relative_config=True)
    with app.app_context():
        init_db(app)
    register_dash(flask_app_name=app_name, flask_app=app)

    return app
