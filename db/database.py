import datetime

from env_vars import db_uri
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import pandas as pd

db = SQLAlchemy()


def init_db(app=None):
    if app is None:
        # Create flask application for db to use app context
        app = Flask(__name__)
    db_config_dict = {
        "pool_pre_ping": True,
        "pool_size": 5,
        # recycle connection after 3600 seconds (one hour)
        "pool_recycle": 3600,
        "pool_timeout": 30,
    }
    with app.app_context():
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
        - cvss_v3_version = impact["baseMetricV3"]["cvssV3"]["version"]
        - cvss_v3_vector_string = impact["baseMetricV3"]["cvssV3"]["vectorString"]
        - cvss_v3_attack_vector = impact["baseMetricV3"]["cvssV3"]["attackVector"]
        - cvss_v3_attack_complexity = impact["baseMetricV3"]["cvssV3"]["attackComplexity"]
        - cvss_v3_privileges_required = impact["baseMetricV3"]["cvssV3"]["privilegesRequired"]
        - cvss_v3_user_interaction = impact["baseMetricV3"]["cvssV3"]["userInteraction"]
        - cvss_v3_scope = impact["baseMetricV3"]["cvssV3"]["scope"]
        - cvss_v3_confidentiality_impact = impact["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
        - cvss_v3_integrity_impact = impact["baseMetricV3"]["cvssV3"]["integrityImpact"]
        - cvss_v3_availability_impact = impact["baseMetricV3"]["cvssV3"]["availabilityImpact"]
        - cvss_v3_base_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        - cvss_v3_base_severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
        - base_metric_v3_exploitability_score = impact["baseMetricV3"]["exploitabilityScore"]
        - base_metric_v3_impact_score = impact["baseMetricV3"]["impactScore"]
        - cvss_v3_impact_score = impact["baseMetricV3"]["impactScore"]
        - cvss_v2_version = impact["baseMetricV2"]["cvssV2"]["version"]
        - cvss_v2_vector_string = impact["baseMetricV2"]["cvssV2"]["vectorString"]
        - cvss_v2_access_vector = impact["baseMetricV2"]["cvssV2"]["accessVector"]
        - cvss_v2_access_complexity = impact["baseMetricV2"]["cvssV2"]["accessComplexity"]
        - cvss_v2_authentication = impact["baseMetricV2"]["cvssV2"]["authentication"]
        - cvss_v2_confidentiality_impact = impact["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
        - cvss_v2_integrity_impact = impact["baseMetricV2"]["cvssV2"]["integrityImpact"]
        - cvss_v2_availability_impact = impact["baseMetricV2"]["cvssV2"]["availabilityImpact"]
        - cvss_v2_base_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
        - base_metric_v2_severity = impact["baseMetricV2"]["severity"]
        - base_metric_v2_exploitability_score = impact["baseMetricV2"]["exploitabilityScore"]
        - base_metric_v2_impact_score = impact["baseMetricV2"]["impactScore"]
        - base_metric_v2_obtain_all_privilege = impact["baseMetricV2"]["obtainAllPrivilege"]
        - base_metric_v2_obtain_user_privilege = impact["baseMetricV2"]["obtainUserPrivilege"]
        - base_metric_v2_obtain_other_privilege = impact["baseMetricV2"]["obtainOtherPrivilege"]
        - base_metric_v2_user_interaction_required = impact["baseMetricV2"]["userInteractionRequired"]
        - published_date = publishedDate
        - last_modified_date = lastModifiedDate
        - full_cve_json = ["CVE_Items"][0]
        - record_creation_date = generated by SQLAlchemy
    """

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(75), nullable=False)
    description = db.Column(db.Text, nullable=False)
    cvss_v3_version = db.Column(db.String(75))
    cvss_v3_vector_string = db.Column(db.String(75))
    cvss_v3_attack_vector = db.Column(db.String(75))
    cvss_v3_attack_complexity = db.Column(db.String(75))
    cvss_v3_privileges_required = db.Column(db.String(75))
    cvss_v3_user_interaction = db.Column(db.String(75))
    cvss_v3_scope = db.Column(db.String(75))
    cvss_v3_confidentiality_impact = db.Column(db.String(75))
    cvss_v3_integrity_impact = db.Column(db.String(75))
    cvss_v3_availability_impact = db.Column(db.String(75))
    cvss_v3_base_score = db.Column(db.Float)
    cvss_v3_base_severity = db.Column(db.String(75))
    base_metric_v3_exploitability_score = db.Column(db.Float)
    base_metric_v3_impact_score = db.Column(db.Float)
    cvss_v2_version = db.Column(db.String(75))
    cvss_v2_vector_string = db.Column(db.String(75))
    cvss_v2_access_vector = db.Column(db.String(75))
    cvss_v2_access_complexity = db.Column(db.String(75))
    cvss_v2_authentication = db.Column(db.String(75))
    cvss_v2_confidentiality_impact = db.Column(db.String(75))
    cvss_v2_integrity_impact = db.Column(db.String(75))
    cvss_v2_availability_impact = db.Column(db.String(75))
    cvss_v2_base_score = db.Column(db.Float)
    base_metric_v2_severity = db.Column(db.String(75))
    base_metric_v2_exploitability_score = db.Column(db.Float)
    base_metric_v2_impact_score = db.Column(db.Float)
    base_metric_v2_obtain_all_privilege = db.Column(db.Boolean)
    base_metric_v2_obtain_user_privilege = db.Column(db.Boolean)
    base_metric_v2_obtain_other_privilege = db.Column(db.Boolean)
    base_metric_v2_user_interaction_required = db.Column(db.Boolean)
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified_date = db.Column(db.DateTime)
    full_cve_json = db.Column(db.JSON, nullable=False)
    record_creation_date = db.Column(
        db.DateTime, nullable=False, default=datetime.datetime.utcnow
    )

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
        result_set = CVE.query.filter_by(cve_id=nvd_cve_id).all()
        return result_set

    @staticmethod
    def get_last_modified_record_by_cve_id(nvd_cve_id):
        """
        Return cve with the most recent last_modified_date.
        """

        result_set = CVE.get_records_by_cve_id(nvd_cve_id)

        if result_set:
            last_modified_record = result_set[0]

            for record in result_set:
                if last_modified_record is None:
                    last_modified_record = record

                elif (
                    record.last_modified_date > last_modified_record.last_modified_date
                ):
                    last_modified_record = record

        else:
            last_modified_record = None

        return last_modified_record

    @staticmethod
    def get_entities_dict():
        return {
            "id": CVE.id,
            "cve_id": CVE.cve_id,
            "description": CVE.description,
            "cvss_v3_version": CVE.cvss_v3_version,
            "cvss_v3_vector_string": CVE.cvss_v3_vector_string,
            "cvss_v3_attack_vector": CVE.cvss_v3_attack_vector,
            "cvss_v3_attack_complexity": CVE.cvss_v3_attack_complexity,
            "cvss_v3_privileges_required": CVE.cvss_v3_privileges_required,
            "cvss_v3_user_interaction": CVE.cvss_v3_user_interaction,
            "cvss_v3_scope": CVE.cvss_v3_scope,
            "cvss_v3_confidentiality_impact": CVE.cvss_v3_confidentiality_impact,
            "cvss_v3_integrity_impact": CVE.cvss_v3_integrity_impact,
            "cvss_v3_availability_impact": CVE.cvss_v3_availability_impact,
            "cvss_v3_base_score": CVE.cvss_v3_base_score,
            "cvss_v3_base_severity": CVE.cvss_v3_base_severity,
            "base_metric_v3_exploitability_score": CVE.base_metric_v3_exploitability_score,
            "base_metric_v3_impact_score": CVE.base_metric_v3_impact_score,
            "cvss_v2_version": CVE.cvss_v2_version,
            "cvss_v2_vector_string": CVE.cvss_v2_vector_string,
            "cvss_v2_access_vector": CVE.cvss_v2_access_vector,
            "cvss_v2_access_complexity": CVE.cvss_v2_access_complexity,
            "cvss_v2_authentication": CVE.cvss_v2_authentication,
            "cvss_v2_confidentiality_impact": CVE.cvss_v2_confidentiality_impact,
            "cvss_v2_integrity_impact": CVE.cvss_v2_integrity_impact,
            "cvss_v2_availability_impact": CVE.cvss_v2_availability_impact,
            "cvss_v2_base_score": CVE.cvss_v2_base_score,
            "base_metric_v2_severity": CVE.base_metric_v2_severity,
            "base_metric_v2_exploitability_score": CVE.base_metric_v2_exploitability_score,
            "base_metric_v2_impact_score": CVE.base_metric_v2_impact_score,
            "base_metric_v2_obtain_all_privilege": CVE.base_metric_v2_obtain_all_privilege,
            "base_metric_v2_obtain_user_privilege": CVE.base_metric_v2_obtain_user_privilege,
            "base_metric_v2_obtain_other_privilege": CVE.base_metric_v2_obtain_other_privilege,
            "base_metric_v2_user_interaction_required": CVE.base_metric_v2_user_interaction_required,
            "published_date": CVE.published_date,
            "last_modified_date": CVE.last_modified_date,
            "full_cve_json": CVE.full_cve_json,
            "record_creation_date": CVE.record_creation_date,
        }

    def __repr__(self):
        return "<CVE %r>" % self.cve_id


class CPE_Match(db.Model):

    """
    JSON schema
        {
            "cpe23Uri" : "cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*",
            "cpe_name" : 
                [ 
                    {
                    "cpe23Uri" : "cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*"
                    } 
                ]
        }
    This model represents a single `match` from the `matches` list in nvdcpematch-1.0.json.
    """

    id = db.Column(db.Integer, primary_key=True)
    cpe_23_uri = db.Column(db.String, nullable=False)
    cpe_name = db.Column(
        db.Text, nullable=True
    )  # This is a list of dicts that we will turn into a comma sep string on model creation.
    full_cpe_match_json = db.Column(db.JSON, nullable=False)
    record_creation_date = db.Column(
        db.DateTime, nullable=False, default=datetime.datetime.utcnow
    )

    __tablename__ = "cpe_match"

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_records_by_cpe_23_uri(cpe_23_uri):
        """
        Return result set of all records with input cpe_23_uri
        """
        result_set = CPE_Match.query.filter_by(cpe_23_uri=cpe_23_uri).all()
        return result_set

    def __repr__(self):
        return "<CPE_Match %r>" % self.cpe_23_uri


def get_cve_query_df_with_columns(col_names_list=None):
    """
    Using col_names_list to create an entities list create a SQLAlchemy query statement.
    Uses the paramaterized query statement with pandas read_sql to return a dataframe with query result. 
    """
    entities_dict = CVE.get_entities_dict()
    if col_names_list is None:
        entities_list = entities_dict.values()
    else:
        entities_list = [entities_dict[col_name] for col_name in col_names_list]

    query_statement = (
        CVE.query.order_by(CVE.published_date.asc())
        .with_entities(*entities_list)
        .statement
    )

    return pd.read_sql(query_statement, db.engine)


def get_cvss_v3_cols():
    return [key for key in CVE.get_entities_dict().keys() if "v2" not in key]


def get_cvss_v2_cols():
    return [key for key in CVE.get_entities_dict().keys() if "v3" not in key]
