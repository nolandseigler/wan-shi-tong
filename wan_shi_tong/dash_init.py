from dash import Dash
from wan_shi_tong.dash_layout import dash_route_layout
from wan_shi_tong.dash_callbacks import register_dash_callbacks


def register_dash(flask_app_name, flask_app):

    dash_route = Dash(
        flask_app_name,
        server=flask_app,
        external_stylesheets=["https://codepen.io/chriddyp/pen/bWLwgP.css"],
    )
    dash_route.layout = dash_route_layout
    register_dash_callbacks(dash_route)

    """
    What do we want to do?

    1. Get CPE and CVE data from NVD API:
        TODO:
        - What data is there?
        TODO:
        - What format does it come back in.
            - https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
        - What paramaters can be used to search, sort, and filter?
            TODO:
            - Within the API
            - Once the data is here we have access to the data and will put it in a pandas df.
        - Should we store the data in our own database?
            - The docs mentioned using a data feed for each year to store data
            and then pulling from one of the two update feeds."
                - DB will be postgres (I need to practice with it)
                TODO:
                - DB Schema?

    2. Display that data in a useful way.
        - Show number of CVE per year over time.
            period JANXX - DECXX
            fig = px.scatter(df, x="month", y="average cvss score",
                    size="number_cve", color="continent"(IDK), hover_name="cve_name_list",
                    log_x=True, size_max=60(IDK))
    """
