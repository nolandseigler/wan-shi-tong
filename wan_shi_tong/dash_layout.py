import dash_html_components as html
import dash_core_components as dcc

from wan_shi_tong.dash_callbacks import cve_cvss_v3_df as df


dash_route_layout = html.Div(
    [
        html.Div(
            [
                dcc.Slider(
                    id="month-slider",
                    min=df["published_date"].dt.month.min(),
                    max=df["published_date"].dt.month.max(),
                    value=df["published_date"].dt.month.min(),
                    marks={
                        str(month): str(month)
                        for month in df["published_date"].dt.month.unique()
                    },
                    step=None,
                ),
                dcc.Slider(
                    id="year-slider",
                    min=df["published_date"].dt.year.min(),
                    max=df["published_date"].dt.year.max(),
                    value=df["published_date"].dt.year.max(),
                    marks={
                        str(year): str(year)
                        for year in df["published_date"].dt.year.unique()
                    },
                    step=None,
                ),
            ],
            style={
                "background": "white",
                "padding-top": "2rem",
                "position": "fixed",
                "top": 0,
                "width": "100%",
                "zIndex": 999,
            },
        ),
        html.Div(
            [
                dcc.Graph(id="px_box_cvss_v3_base_score"),
                dcc.Graph(id="px_hist_cvss_v3_base_severity"),
                dcc.Graph(id="px_hist_cvss_v3_attack_vector"),
                dcc.Graph(id="px_hist_cvss_v3_attack_complexity"),
                dcc.Graph(id="px_hist_cvss_v3_privileges_required"),
                dcc.Graph(id="px_hist_cvss_v3_user_interaction"),
                dcc.Graph(id="px_hist_cvss_v3_confidentiality_impact"),
                dcc.Graph(id="px_hist_cvss_v3_integrity_impact"),
                dcc.Graph(id="px_hist_cvss_v3_availability_impact"),
            ]
        ),
    ],
    style={"zIndex": 998},
)
