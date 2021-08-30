import dash_html_components as html
import dash_core_components as dcc

from wan_shi_tong.dash_callbacks import cve_cvss_v3_df as df


dash_route_layout = html.Div([
    dcc.Graph(id="graph-with-slider"),
    dcc.Slider(
        id="month-slider",
        min=df["published_date"].dt.month.min(),
        max=df["published_date"].dt.month.max(),
        value=df["published_date"].dt.month.min(),
        marks={str(month): str(month) for month in df["published_date"].dt.month.unique()},
        step=None
    ),
    dcc.Slider(
        id="year-slider",
        min=df["published_date"].dt.year.min(),
        max=df["published_date"].dt.year.max(),
        value=df["published_date"].dt.year.max(),
        marks={str(year): str(year) for year in df["published_date"].dt.year.unique()},
        step=None
    )
])