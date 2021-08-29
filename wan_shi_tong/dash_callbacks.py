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
cve_cvss_v3_df["x_col_for_display"] = cve_cvss_v3_df.apply(lambda x: str(x["published_date"])[:10], axis=1)

px_scatter_fig_objs = {}

# create all of the figures on app creation. This means stale data for now but at the moment the app crashes when year > 2015
for pub_date_year in cve_cvss_v3_df["published_date"].dt.year.unique():
    # https://plotly.com/python/line-and-scatter/
    filtered_df = cve_cvss_v3_df.loc[cve_cvss_v3_df["published_date"].dt.year == pub_date_year]
    figure = px.scatter(
        filtered_df, x="x_col_for_display", y="base_metric_v3_impact_score",
        size="base_metric_v3_impact_score",
        color="cve_id", hover_name="cve_id", render_mode="webgl"
    )
    figure.update_layout(transition_duration=500)
    px_scatter_fig_objs["pub_date_year"] = figure

def register_dash_callbacks(dash_route):
    
    @dash_route.callback(
        Output('graph-with-slider', 'figure'),
        [Input('year-slider', 'value')]
    )
    def update_figure(selected_year):
        """
        This function uses a slider to select a year to display info for the px.scatter.
        The dropdown queries NVD for the CVEs for that year.

        base uri:  https://services.nvd.nist.gov/rest/json/

        example query uri: https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=0&resultsPerPage=200&pubStartDate=2019-01-01T00:00:00:000%20UTC-05:00&pubEndDate=2019-12-31T00:00:00:000%20UTC-04:59
        """
        
        # filtered_df = cve_cvss_v3_df.loc[cve_cvss_v3_df["published_date"].dt.year == selected_year]
        

        # fig = px.scatter(
        #     filtered_df, x="x_col_for_display", y="base_metric_v3_impact_score", 
        #     size="base_metric_v3_impact_score", color="cve_id", hover_name="cve_id", 
        # )
        

        # fig.update_layout(transition_duration=500)

        return px_scatter_fig_objs[selected_year]