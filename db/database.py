from flask_sqlalchemy import SQLAlchemy
from env_vars import db_uri

db = SQLAlchemy()

def init_db(app):
    db_config_dict = {
        "pool_pre_ping": True,
        "pool_size": 5,
        # recycle connection after 3600 seconds (one hour)
        "pool_recycle": 3600,
        "pool_timeout": 30
    }
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = db_config_dict
    db.init_app(app)
    db.create_all()



class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    __tablename__ = "cve"

    def __repr__(self):
        return '<User %r>' % self.username

