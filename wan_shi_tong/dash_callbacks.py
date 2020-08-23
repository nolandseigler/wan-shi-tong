from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px

df = pd.read_csv('https://raw.githubusercontent.com/plotly/datasets/master/gapminderDataFiveYear.csv')

def register_dash_callbacks(dash_route):
    
    @dash_route.callback(
        Output('graph-with-slider', 'figure'),
        [Input('year-slider', 'value')])
    def update_figure(selected_year):
        """
        This function uses a slider to select a year to display info for the px.scatter.
        The dropdown queries NVD for the CVEs for that year.

        base uri:  https://services.nvd.nist.gov/rest/json/

        example query uri: https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=0&resultsPerPage=200&pubStartDate=2019-01-01T00:00:00:000%20UTC-05:00&pubEndDate=2019-12-31T00:00:00:000%20UTC-04:59
        """
        filtered_df = df[df.year == selected_year]

        fig = px.scatter(filtered_df, x="gdpPercap", y="lifeExp", 
                        size="pop", color="continent", hover_name="country", 
                        log_x=True, size_max=55)

        fig.update_layout(transition_duration=500)

        return fig