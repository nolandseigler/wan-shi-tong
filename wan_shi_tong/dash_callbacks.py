from dash.dependencies import Input, Output
from flask import Flask
import plotly.express as px

from db.database import get_cvss_v2_cols, get_cvss_v3_cols, get_cve_query_df_with_columns, init_db

temp_app = Flask(__name__)
init_db(temp_app)
with temp_app.app_context():
    full_df = get_cve_query_df_with_columns()



# This leaves some records not included because they have not been assigned versions or score information.
cve_cvss_v3_df = full_df[get_cvss_v3_cols()].loc[full_df["cvss_v3_version"].notna()]
cve_cvss_v2_df = full_df[get_cvss_v2_cols()].loc[full_df["cvss_v2_version"].notna()]

# Add x col for display
cve_cvss_v3_df["date_published"] = cve_cvss_v3_df.apply(lambda x: str(x["published_date"])[8:10], axis=1)

px_box_fig_objs = {}

# create all of the figures on app creation. This means stale data for now but at the moment the app crashes when year > 2015
for pub_date_year in cve_cvss_v3_df["published_date"].dt.year.unique():
    # TODO: Dont nest the for loops.
    for pub_date_month in cve_cvss_v3_df["published_date"].dt.month.unique():
        filtered_df = cve_cvss_v3_df.loc[(cve_cvss_v3_df["published_date"].dt.year == pub_date_year) & (cve_cvss_v3_df["published_date"].dt.month == pub_date_month)]
        figure = px.box(filtered_df, x="date_published", y="cvss_v3_base_score", points="all")
        figure.update_layout(transition_duration=500)
        px_box_fig_objs[f"{pub_date_year}-{pub_date_month}"] = figure


def register_dash_callbacks(dash_route):
    
    @dash_route.callback(
        Output('graph-with-slider', 'figure'),
        [
            Input('month-slider', 'value'),
            Input('year-slider', 'value'),
        ]
    )
    def update_figure(selected_month, selected_year):
        """
        This function uses a slider to select a year to display info for the px.scatter.
        The dropdown queries NVD for the CVEs for that year.

        base uri:  https://services.nvd.nist.gov/rest/json/

        example query uri: https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=0&resultsPerPage=200&pubStartDate=2019-01-01T00:00:00:000%20UTC-05:00&pubEndDate=2019-12-31T00:00:00:000%20UTC-04:59
        """

        return px_box_fig_objs[f"{selected_year}-{selected_month}"]