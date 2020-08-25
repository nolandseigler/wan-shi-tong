import datetime
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

    """
    JSON schema
        - https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
    This model represents a single CVE_Item from the json response of a query to the NVD CVE rest api.
    Example query: https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
    Example model is derived from result["CVE_Items"][0]
        - id = generated by SQLAlchemy
        - cve_id = cve["CVE_data_meta"]["ID"]
        - description = description["description_data"][0]["value"]
        - cvss_v3_base_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        - cvss_v3_base_severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
        - cvss_v3_impact_score = impact["baseMetricV3"]["impactScore"]
        - cvss_v2_base_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
        - cvss_v2_severity = impact["baseMetricV2"]["severity"]
        - cvss_v2_impact_score = impact["baseMetricV2"]["impactScore"]
        - published_date = publishedDate
        - last_modified_date = lastModifiedDate
        - full_cve_json = ["CVE_Items"][0]
        - record_creation_date = generated by SQLAlchemy
    """
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(25), nullable=False)
    description = db.Column(db.Text, nullable=False)
    cvss_v3_base_score = db.Column(db.Integer)
    cvss_v3_base_severity = db.Column(db.String(25))
    cvss_v3_impact_score = db.Column(db.Integer)
    cvss_v2_base_score = db.Column(db.Integer)
    cvss_v2_severity = db.Column(db.String(25))
    cvss_v2_impact_score = db.Column(db.Integer)
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified_date = db.Column(db.DateTime)
    full_cve_json = db.Column(db.JSON, nullable=False)
    record_creation_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)



    __tablename__ = "cve"

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def is_record_present(nvd_cve_id):
        """
        Return true if a record in the table contains the nvd_cve_id
        """
        result = CVE.query.filter_by(cve_id=nvd_cve_id).scalar()
        return result is not None

    @staticmethod
    def get_records_by_cve_id(nvd_cve_id):
        """
        Return result set of all records with input cve_id
        """
        results_set = CVE.query.filter_by(cve_id=nvd_cve_id).all()
        return result_set

    @staticmethod
    def get_last_modified_record_by_cve_id(nvd_cve_id):
        """
        Return cve with the most recent last_modified_date.
        """
        
        results_set = self.get_records_by_cve_id(nvd_cve_id)

        last_modified_record = None


        for record in result_set:
            if last_modified_record is None:
                last_modified_record = record
            elif record.last_modified_date > last_modified_record:
                last_modified_record = record

        return last_modified_record


    def __repr__(self):
        return '<User %r>' % self.username

