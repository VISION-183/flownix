# Import Module -- Start

import pandas
import subprocess
import sqlite3
import dash
import json
import argparse
import dash_bootstrap_components
import pathlib

# Import Module -- End

# Function Declaration -- Start

def parse_arg():

    # Create the parser object
    parser = argparse.ArgumentParser(description="Flownix Dashboard", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Define arguments
    parser.add_argument('--config-path', type=str, required=False, default='config/flownix.json', help="Configuration file path")

    # Parse the arguments
    arg = parser.parse_args()

    return arg

def load_config():
    path = pathlib.Path(arg.config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)

def read_local_traffic_table(page_size=20, page_current=0, filter_query=None, known_port=False, human_readable=False, sort_option=[]):

    conn = sqlite3.connect(config["collector"]["local_db_path"])

    if known_port is False and human_readable is False:

        base_query = """
            SELECT
                src_domain,
                src_ip,
                src_port,
                dst_domain,
                dst_ip,
                dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                total_length,
                last_updated
            FROM traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        if sort_option:

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is False and human_readable is True:

        base_query = """
            SELECT
                src_domain,
                src_ip,
                src_port,
                dst_domain,
                dst_ip,
                dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                total_length AS total_length_raw,
                CASE
                    WHEN total_length IS NULL OR total_length = 0 THEN '0 B'
                    WHEN total_length >= 1099511627776 THEN printf('%.2f TB', total_length / 1099511627776.0)
                    WHEN total_length >= 1073741824 THEN printf('%.2f GB', total_length / 1073741824.0)
                    WHEN total_length >= 1048576 THEN printf('%.2f MB', total_length / 1048576.0)
                    WHEN total_length >= 1024 THEN printf('%.2f KB', total_length / 1024.0)
                    ELSE printf('%.2f B', total_length * 1.0)
                END AS total_length,
                last_updated
            FROM traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        if sort_option and sort_option[0] == 'total_length':

            base_query += f" ORDER BY total_length_raw {sort_option[1]}"

        elif sort_option and sort_option[0] != 'total_length':

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is True and human_readable is False:

        base_query = """
            SELECT
                src_domain,
                src_ip,
                CASE 
                    WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE src_port
                END AS src_port,
                dst_domain,
                dst_ip,
                CASE 
                    WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE dst_port
                END AS dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                SUM(total_length) AS total_length,
                MAX(last_updated) AS last_updated
            FROM traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        base_query += f"""
        GROUP BY
            src_domain,
            src_ip,
            CASE WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE src_port END,
            dst_domain,
            dst_ip,
            CASE WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE dst_port END,
            interface,
            direction,
            network_proto,
            trans_proto,
            tos,
            desc,
            process_name,
            process_cmd,
            process_arg,
            parent_process_name,
            parent_process_cmd,
            parent_process_arg
        """

        if sort_option:

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is True and human_readable is True:

        base_query = """
            SELECT
                src_domain,
                src_ip,
                CASE 
                    WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE src_port
                END AS src_port,
                dst_domain,
                dst_ip,
                CASE 
                    WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE dst_port
                END AS dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                SUM(total_length) AS total_length_raw,                
                CASE
                    WHEN SUM(total_length) IS NULL OR SUM(total_length) = 0 THEN '0 B'
                    WHEN SUM(total_length) >= 1099511627776 THEN printf('%.2f TB', SUM(total_length) / 1099511627776.0)
                    WHEN SUM(total_length) >= 1073741824 THEN printf('%.2f GB', SUM(total_length) / 1073741824.0)
                    WHEN SUM(total_length) >= 1048576 THEN printf('%.2f MB', SUM(total_length) / 1048576.0)
                    WHEN SUM(total_length) >= 1024 THEN printf('%.2f KB', SUM(total_length) / 1024.0)
                    ELSE printf('%.2f B', SUM(total_length) * 1.0)
                END AS total_length,
                MAX(last_updated) AS last_updated
            FROM traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        base_query += f"""
        GROUP BY
            src_domain,
            src_ip,
            CASE WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE src_port END,
            dst_domain,
            dst_ip,
            CASE WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE dst_port END,
            interface,
            direction,
            network_proto,
            trans_proto,
            tos,
            desc,
            process_name,
            process_cmd,
            process_arg,
            parent_process_name,
            parent_process_cmd,
            parent_process_arg
        """

        if sort_option and sort_option[0] == 'total_length':

            base_query += f" ORDER BY total_length_raw {sort_option[1]}"

        elif sort_option and sort_option[0] != 'total_length':

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    if page_size == "U":

        df_base = pandas.read_sql(base_query,conn)

        conn.close()

        return df_base, 0

    else:

        df_count = pandas.read_sql(base_query,conn)

        base_query += f" LIMIT {page_size} OFFSET {page_current * page_size}"

        df_base = pandas.read_sql(base_query,conn)

        page_count = len(df_count) // page_size + (1 if len(df_count) % page_size else 0)

        conn.close()

        return df_base, page_count

def read_receiver_traffic_table(page_size=20, page_current=0, filter_query=None, known_port=False, human_readable=False, sort_option=[]):

    conn = sqlite3.connect(config["receiver"]["receiver_db_path"])

    if known_port is False and human_readable is False:

        base_query = """
            SELECT
                sender_domain,
                sender_ip, 
                src_domain,
                src_ip,
                src_port,
                dst_domain,
                dst_ip,
                dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                total_length,
                last_updated
            FROM receiver_traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        if sort_option:

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is False and human_readable is True:

        base_query = """
            SELECT
                sender_domain,
                sender_ip,
                src_domain,
                src_ip,
                src_port,
                dst_domain,
                dst_ip,
                dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                total_length AS total_length_raw,
                CASE
                    WHEN total_length IS NULL OR total_length = 0 THEN '0 B'
                    WHEN total_length >= 1099511627776 THEN printf('%.2f TB', total_length / 1099511627776.0)
                    WHEN total_length >= 1073741824 THEN printf('%.2f GB', total_length / 1073741824.0)
                    WHEN total_length >= 1048576 THEN printf('%.2f MB', total_length / 1048576.0)
                    WHEN total_length >= 1024 THEN printf('%.2f KB', total_length / 1024.0)
                    ELSE printf('%.2f B', total_length * 1.0)
                END AS total_length,
                last_updated
            FROM receiver_traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        if sort_option and sort_option[0] == 'total_length':

            base_query += f" ORDER BY total_length_raw {sort_option[1]}"

        elif sort_option and sort_option[0] != 'total_length':

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is True and human_readable is False:

        base_query = """
            SELECT
                sender_domain,
                sender_ip,
                src_domain,
                src_ip,
                CASE 
                    WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE src_port
                END AS src_port,
                dst_domain,
                dst_ip,
                CASE 
                    WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE dst_port
                END AS dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                SUM(total_length) AS total_length,
                MAX(last_updated) AS last_updated
            FROM receiver_traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        base_query += f"""
        GROUP BY
            sender_domain,
            sender_ip,
            src_domain,
            src_ip,
            CASE WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE src_port END,
            dst_domain,
            dst_ip,
            CASE WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE dst_port END,
            interface,
            direction,
            network_proto,
            trans_proto,
            tos,
            desc,
            process_name,
            process_cmd,
            process_arg,
            parent_process_name,
            parent_process_cmd,
            parent_process_arg
        """

        if sort_option:

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    elif known_port is True and human_readable is True:

        base_query = """
            SELECT
                sender_domain,
                sender_ip,
                src_domain,
                src_ip,
                CASE 
                    WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE src_port
                END AS src_port,
                dst_domain,
                dst_ip,
                CASE 
                    WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known'
                    ELSE dst_port
                END AS dst_port,
                interface,
                direction,
                network_proto,
                trans_proto,
                tos,
                desc,
                process_name,
                process_cmd,
                process_arg,
                parent_process_name,
                parent_process_cmd,
                parent_process_arg,
                SUM(total_length) AS total_length_raw,                
                CASE
                    WHEN SUM(total_length) IS NULL OR SUM(total_length) = 0 THEN '0 B'
                    WHEN SUM(total_length) >= 1099511627776 THEN printf('%.2f TB', SUM(total_length) / 1099511627776.0)
                    WHEN SUM(total_length) >= 1073741824 THEN printf('%.2f GB', SUM(total_length) / 1073741824.0)
                    WHEN SUM(total_length) >= 1048576 THEN printf('%.2f MB', SUM(total_length) / 1048576.0)
                    WHEN SUM(total_length) >= 1024 THEN printf('%.2f KB', SUM(total_length) / 1024.0)
                    ELSE printf('%.2f B', SUM(total_length) * 1.0)
                END AS total_length,
                MAX(last_updated) AS last_updated
            FROM receiver_traffic
        """

        if filter_query:

            base_query += f" WHERE {filter_query}"

        base_query += f"""
        GROUP BY
            sender_domain,
            sender_ip,
            src_domain,
            src_ip,
            CASE WHEN src_port != 'None' AND CAST(src_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE src_port END,
            dst_domain,
            dst_ip,
            CASE WHEN dst_port != 'None' AND CAST(dst_port AS INTEGER) > 1024 THEN 'Not well-known' ELSE dst_port END,
            interface,
            direction,
            network_proto,
            trans_proto,
            tos,
            desc,
            process_name,
            process_cmd,
            process_arg,
            parent_process_name,
            parent_process_cmd,
            parent_process_arg
        """

        if sort_option and sort_option[0] == 'total_length':

            base_query += f" ORDER BY total_length_raw {sort_option[1]}"

        elif sort_option and sort_option[0] != 'total_length':

            base_query += f" ORDER BY {sort_option[0]} {sort_option[1]}"

    if page_size == "U":

        df_base = pandas.read_sql(base_query,conn)

        conn.close()

        return df_base, 0

    else:

        df_count = pandas.read_sql(base_query,conn)

        base_query += f" LIMIT {page_size} OFFSET {page_current * page_size}"

        df_base = pandas.read_sql(base_query,conn)

        page_count = len(df_count) // page_size + (1 if len(df_count) % page_size else 0)

        conn.close()

        return df_base, page_count

def create_dash_app():

    app = dash.Dash(title="Flownix")

    # Layout of the app
    app.layout = dash.html.Div([

        dash.dcc.Location(id='url', refresh=False),  # Tracks URL changes
        dash.dcc.Store(
            id='store',
            data={
                'traffic_setting': {'checklist': []},
                'configuration':{},
            },
            storage_type='local'
            ),

        dash_bootstrap_components.Modal(
            [
                dash_bootstrap_components.ModalHeader(
                    dash_bootstrap_components.ModalTitle(

                        id='modal-capturing-title',
                    ),
                    id='modal-capturing-header'
                ),

                dash_bootstrap_components.ModalBody(
                    id='modal-capturing-body'
                ),

                dash_bootstrap_components.ModalFooter(
                    id='modal-capturing-footer'
                ),
            ],
            id='modal-capturing',
            is_open=False,
        ),

        # Interval to interval-auto-refresh data every 10 seconds
        dash.dcc.Interval(
            id='interval-auto-refresh',
            interval=10000,  # Time interval in milliseconds (10000ms = 10 seconds)
            n_intervals=0  # Number of times the callback has been triggered
        ),

        dash.html.Div([

            dash.html.Div([

                dash_bootstrap_components.Container([

                    dash_bootstrap_components.Row([

                        dash_bootstrap_components.Col([

                            dash.html.Div([

                                dash_bootstrap_components.Navbar(

                                    # Button to open the offcanvas sidebar with Font Awesome hamburger icon
                                    dash_bootstrap_components.Button(
                                        dash.html.I(className="fa fa-bars"),  # Font Awesome hamburger icon (three lines)
                                        id="button-open-sidebar",
                                        color="primary",
                                        n_clicks=0,
                                        style={"font-size": "15px", "transition":"transform 0.3s ease-in-out", "margin-left":"10px"}  # Adjust icon size if needed
                                    ),
                                    
                                color="dark",
                                dark=True,
                                fixed="top",

                                ),

                            ], id="div-navbar"),

                            dash.html.Div([

                                # Offcanvas component for the sidebar
                                dash_bootstrap_components.Offcanvas(
                                    dash_bootstrap_components.Nav([
                                        dash_bootstrap_components.NavLink("Home", id="nav-offcanvas-navlink-home", href="/", active="exact"),
                                        dash_bootstrap_components.NavLink("Traffic", id="nav-offcanvas-navlink-traffic", href="/traffic", active="exact"),
                                        dash_bootstrap_components.NavLink("About", id="nav-offcanvas-navlink-about", href="/about", active="exact"),
                                    ], id="nav-offcanvas", vertical=True, pills=True),  # Menu links inside sidebar
                                    id="offcanvas",
                                    close_button=False,
                                    backdrop=False,
                                    title="Sidebar",
                                    is_open=False,
                                    placement="start",  # Sidebar comes in from the left ('start')
                                    scrollable=True,
                                    style={'width': '250px'}  # Set the sidebar width
                                ),

                            ], id='div-offcanvas' ),

                        ]),

                    ]),

                ], fluid=True, style={"padding":"0px"}),

            ], id="div-header"),

            dash.html.Div([

                dash_bootstrap_components.Container([

                    dash_bootstrap_components.Row([

                        dash_bootstrap_components.Col([

                            dash.html.Div([


                            ], id='div-body-side'),

                        ], width={"size": 3}),

                        dash_bootstrap_components.Col([

                            dash.html.Div([


                            ], id='div-body-main'),

                        ], width={"size": 9}),

                    ]),

                ], fluid=True, style={"padding":"0px"}),

            ], id='div-body', style={'transition':'transform 0.3s ease-in-out', 'word-wrap':'break-word', 'margin-top': '52.5px'}),  # This will display content based on URL

        ], id='div-page'),

    ])

    @app.callback(
        dash.dependencies.Output('store', 'data'),
        dash.dependencies.Input('checklist-traffic-setting', 'value'),
        dash.dependencies.State('store', 'data'),
    )
    def store_data(checklist_traffic_setting_value, store_data):

        triggered_prop_id = dash.ctx.triggered[0]['prop_id']

        if triggered_prop_id == 'checklist-traffic-setting.value':

            store_data['traffic_setting']['checklist']=checklist_traffic_setting_value
            return store_data

        else:

            return dash.no_update

    @app.callback(
        dash.dependencies.Output('div-body', 'children'),
        dash.dependencies.Input('url', 'pathname'),
        dash.dependencies.State('store', 'data'),
        dash.dependencies.State('div-body-main', 'children'),
        dash.dependencies.State('div-body-side', 'children'),
    )
    def render_div_content(url_pathname, store_data, div_content_main_children, div_content_side_children):
        if url_pathname == '/':

            return dash_bootstrap_components.Container([

                dash_bootstrap_components.Row([

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.Img(
                                src='assets/background.jpg',
                                style={

                                    'height': '100%',
                                    'width': '100%',
                                    'object-fit': 'cover',
                                    'object-position': 'center'
                                }
                            )

                        ], id='div-body-side', style={'height': 'calc(100vh - 52.5px)', 'object-fit': 'cover', 'object-position': 'center'}),

                    ], width={"size": 9}),

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.H2("Home Page"),
                            dash.html.P("Welcome to the Flownix!"),
                            dash_bootstrap_components.Button('Go to Traffic!', id='button-navlink-traffic', n_clicks=0, href='/traffic'),
                            dash_bootstrap_components.Button('About us', id='button-navlink-about', n_clicks=0, href='/about')

                        ], id='div-body-main', style={'text-align': 'center', 'display': 'flex', 'flex-direction': 'column', 'gap': '10px', 'align-items': 'center'}),

                    ], width={"size": 3}, align='center'),

                ], className="g-0"),

            ], fluid=True, style={"padding":"0px"})

        elif url_pathname == '/traffic':

            return dash_bootstrap_components.Container([

                dash_bootstrap_components.Row([

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.Div([

                                dash_bootstrap_components.Container([

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            dash_bootstrap_components.RadioItems(
                                                options=[
                                                    {'label': 'Local', 'value': 1},
                                                    {'label': 'Receiver', 'value': 2}
                                                ],
                                                value=1,
                                                inline=True,
                                                id='input-radio-mode',
                                            ),

                                        ]),

                                    ]),

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            dash.dcc.Checklist(
                                                id='checklist-traffic-setting',
                                                options=[
                                                    {'label': ' Aggregate not well-known ports', 'value': 'known_port'},
                                                    {'label': ' Human readable', 'value': 'human_readable'},
                                                ],
                                                value=store_data['traffic_setting']['checklist']
                                                ),

                                        ]),

                                    ]),

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            dash_bootstrap_components.Button('Export', id='button-export-traffic-record', n_clicks=0, style={"margin-top":'10px'}),
                                            dash.dcc.Download(id="download-export-traffic-record")

                                        ]),

                                    ]),

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            dash_bootstrap_components.Button(

                                                [
                                                    dash.html.Div([
                                                        dash.html.Div([

                                                        ], id='div-spinner-button-capturing-traffic-record', className='spinner-border spinner-border-sm', style={'margin-right': '5px', 'margin-top': '3px', 'display': 'none'}),

                                                        dash.html.Div(
                                                            id='div-caption-button-capturing-traffic-record'
                                                        ),

                                                    ], id='div-button-capturing-traffic-record', style={'display': 'inline-flex'}),
                                                ],

                                                id='button-capturing-traffic-record',
                                                n_clicks=0,
                                                style={"margin-top":'10px'}
                                                
                                            ),

                                        ]),

                                    ]),

                                ], fluid=True),

                            ], id='div-traffic-setting', style={'margin':'40px', 'border': '1px solid #ccc', 'border-radius': '8px', 'backgroundColor': '#f9f9f9', 'padding': '10px'})

                        ], id='div-body-side'),

                    ], width={"size": 3}),

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.Div([

                                dash_bootstrap_components.Container([

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            # Dash DataTable to display the database contents
                                            dash_bootstrap_components.Textarea(
                                                id='textarea-traffic-filter',
                                                placeholder='Enter SQL WHERE clause ...',
                                                debounce=True,
                                                draggable=False,
                                                rows=2,

                                            ),

                                        ]),

                                    ], style={"margin-bottom":"5px"}),                    

                                    dash_bootstrap_components.Row([

                                        dash_bootstrap_components.Col([

                                            # Dash DataTable to display the database contents
                                            dash.dash_table.DataTable(
                                                id='datatable-traffic',
                                                columns=[],
                                                data=[],
                                                style_table={
                                                    'height': '70vh',
                                                    'overflowY': 'auto',
                                                    'border': '1px solid #ddd',
                                                    'border-radius': '8px',
                                                },
                                                style_cell={
                                                    'textAlign': 'center',
                                                    'padding': '10px',
                                                    'font-size': '14px',
                                                    'font-family': 'Arial, sans-serif',
                                                    'backgroundColor': 'rgba(240, 240, 240, 0.7)',
                                                    'color': '#333',
                                                    'border': '1px solid #ddd',
                                                },
                                                style_header={
                                                    'backgroundColor': 'rgb(50, 150, 255)',
                                                    'color': 'white',
                                                    'fontWeight': 'bold',
                                                    'textAlign': 'center',
                                                    'font-size': '16px',
                                                },
                                                sort_action='custom',  # Enable sorting
                                                sort_mode='single',
                                                sort_by=[],
                                                page_action='custom',
                                                page_size=20,
                                                page_current=0,
                                                filter_action='none',  # Enable filtering

                                            ),

                                        ]),

                                    ]),

                                ], fluid=True),

                            ], id='div-traffic-table', style={'margin':'40px'}),

                        ], id='div-body-main'),

                    ], width={"size": 9}),

                ]),

            ], fluid=True)

        elif url_pathname  == '/about':

            return dash_bootstrap_components.Container([

                dash_bootstrap_components.Row([

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.Img(
                                src='assets/background.jpg',
                                style={

                                    'height': '100%',
                                    'width': '100%',
                                    'object-fit': 'cover',
                                    'object-position': 'center'
                                }
                            )

                        ], id='div-body-side', style={'height': 'calc(100vh - 52.5px)', 'object-fit': 'cover', 'object-position': 'center'}),

                    ], width={"size": 9}),

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.H2("About"),
                            dash.html.P("Flownix is a graphical network traffic analyzer for Linux-based systems developed by 'Mohammad Reza Moghaddasi'"),
                            dash.html.H3("Contact"),
                            dash_bootstrap_components.Button('Github', id='button-navlink-about-github', n_clicks=0, href='https://github.com/VISION-183'),
                            dash_bootstrap_components.Button('Email Me!', id='button-navlink-about-email', n_clicks=0, href='mailto:183.vision.183@gmail.com')

                        ], id='div-body-main', style={'text-align': 'center', 'display': 'flex', 'flex-direction': 'column', 'gap': '10px', 'align-items': 'center'}),

                    ], width={"size": 3}, align='center'),

                ], className="g-0"),

            ], fluid=True, style={"padding":"0px"})

        else:

            return dash_bootstrap_components.Container([

                dash_bootstrap_components.Row([

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.Img(
                                src='assets/background.jpg',
                                style={

                                    'height': '100%',
                                    'width': '100%',
                                    'object-fit': 'cover',
                                    'object-position': 'center'
                                }
                            )

                        ], id='div-body-side', style={'height': 'calc(100vh - 52.5px)', 'object-fit': 'cover', 'object-position': 'center'}),

                    ], width={"size": 9}),

                    dash_bootstrap_components.Col([

                        dash.html.Div([

                            dash.html.H2("404 Error"),
                            dash.html.P("Page Not Found!"),
                            dash_bootstrap_components.Button('Go to Traffic!', id='button-navlink-traffic', n_clicks=0, href='/traffic'),

                        ], id='div-body-main', style={'text-align': 'center', 'display': 'flex', 'flex-direction': 'column', 'gap': '10px', 'align-items': 'center'}),

                    ], width={"size": 3}, align='center'),

                ], className="g-0"),

            ], fluid=True, style={"padding":"0px"})

    @app.callback(
        dash.dependencies.Output('datatable-traffic', 'columns'),
        dash.dependencies.Output('datatable-traffic', 'data'),
        dash.dependencies.Output('datatable-traffic', 'page_count'),
        dash.dependencies.Input('interval-auto-refresh', 'n_intervals'),
        dash.dependencies.Input('store', 'data'),
        dash.dependencies.Input('datatable-traffic', 'sort_by'),
        dash.dependencies.Input('datatable-traffic', 'page_size'),
        dash.dependencies.Input('datatable-traffic', 'page_current'),
        dash.dependencies.Input('textarea-traffic-filter', 'value'),
        dash.dependencies.Input('input-radio-mode', 'value'),
        prevent_initial_call=True
    )
    def render_datatable_traffic_record(interval_auto_refresh_n_intervals, store_data, datatable_traffic_sort_by, datatable_traffic_page_size, datatable_traffic_page_current, textarea_traffic_filter_value, input_radio_mode_value):
        
        if datatable_traffic_sort_by:

            column_id = datatable_traffic_sort_by[0]['column_id']
            ascending = datatable_traffic_sort_by[0]['direction'] == 'asc'

            if input_radio_mode_value == 1:
                traffic_record_df, page_count = read_local_traffic_table(datatable_traffic_page_size, datatable_traffic_page_current, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'],[column_id,'ASC' if ascending else 'DESC'])
            elif input_radio_mode_value == 2:
                traffic_record_df, page_count = read_receiver_traffic_table(datatable_traffic_page_size, datatable_traffic_page_current, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'],[column_id,'ASC' if ascending else 'DESC'])

        else:

            if input_radio_mode_value == 1:
                traffic_record_df, page_count = read_local_traffic_table(datatable_traffic_page_size, datatable_traffic_page_current, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'],[])
            elif input_radio_mode_value == 2:
                traffic_record_df, page_count = read_receiver_traffic_table(datatable_traffic_page_size, datatable_traffic_page_current, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'],[])


        return [{"name": col, "id": col} for col in traffic_record_df.columns], traffic_record_df[traffic_record_df.columns].to_dict('records'), page_count

    # Callback to toggle the sidebar (open/close)
    @app.callback(
        dash.dependencies.Output("offcanvas", "is_open"),
        dash.dependencies.Output("button-open-sidebar", "style"),
        dash.dependencies.Output("div-body", "style"),
        dash.dependencies.Input("button-open-sidebar", "n_clicks"),
        dash.dependencies.Input("nav-offcanvas-navlink-home", "n_clicks"),
        dash.dependencies.Input("nav-offcanvas-navlink-traffic", "n_clicks"),
        dash.dependencies.Input("nav-offcanvas-navlink-about", "n_clicks"),
        dash.dependencies.State("offcanvas", "is_open"),
        dash.dependencies.State("button-open-sidebar", "style"),
        dash.dependencies.State("div-body", "style"),
        prevent_initial_call=True
    )
    def toggle_sidebar(button_open_sidebar_n_clicks, nav_offcanvas_navlink_home_n_clicks, nav_offcanvas_navlink_traffic_n_clicks, nav_offcanvas_navlink_about_n_clicks, offcanvas_is_open, button_open_sidebar_style, div_content_style):

        if offcanvas_is_open and (button_open_sidebar_n_clicks or nav_offcanvas_navlink_traffic_n_clicks or nav_offcanvas_navlink_home_n_clicks or nav_offcanvas_navlink_about_n_clicks):
            div_content_style["transform"] = "translateX(0px)"
            button_open_sidebar_style["transform"] = "translateX(0px)"  # Reset button position
            return not offcanvas_is_open, button_open_sidebar_style, div_content_style
        elif (not offcanvas_is_open) and button_open_sidebar_n_clicks:
            div_content_style["transform"] = "translateX(250px)"
            button_open_sidebar_style["transform"] = "translateX(250px)"  # Move button to the right
            return not offcanvas_is_open, button_open_sidebar_style, div_content_style

    @app.callback(
        dash.dependencies.Output("download-export-traffic-record", "data"),
        dash.dependencies.Input("button-export-traffic-record", "n_clicks"),
        dash.dependencies.State('datatable-traffic', 'data'),
        dash.dependencies.State('store', 'data'),
        dash.dependencies.State('datatable-traffic', 'sort_by'),
        dash.dependencies.State('textarea-traffic-filter', 'value'),
        dash.dependencies.State('input-radio-mode', 'value'),
        prevent_initial_call=True
    )
    def export_traffic_record(button_export_traffic_record_n_clicks, datatable_traffic_data, store_data, datatable_traffic_sort_by, textarea_traffic_filter_value, input_radio_mode_value):

        if datatable_traffic_sort_by:

            column_id = datatable_traffic_sort_by[0]['column_id']
            ascending = datatable_traffic_sort_by[0]['direction'] == 'asc'

            if input_radio_mode_value == 1:
                traffic_record_df, page_count = read_local_traffic_table("U", 0, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'], [column_id,'ASC' if ascending else 'DESC'])
            elif input_radio_mode_value == 2:
                traffic_record_df, page_count = read_receiver_traffic_table("U", 0, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'], [column_id,'ASC' if ascending else 'DESC'])
        
        else:

            if input_radio_mode_value == 1:
                traffic_record_df, page_count = read_local_traffic_table("U", 0, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'], [])
            elif input_radio_mode_value == 2:
                traffic_record_df, page_count = read_receiver_traffic_table("U", 0, textarea_traffic_filter_value, 'known_port' in store_data['traffic_setting']['checklist'], 'human_readable' in store_data['traffic_setting']['checklist'], [])


        json_data = json.dumps(traffic_record_df.to_dict('records'), indent=4)
        # Return the JSON data as content and specify that it's a JSON file
        return dict(content=json_data, filename="traffic_record.json", type="application/json")    

    @app.callback(
        dash.dependencies.Output("div-caption-button-capturing-traffic-record", "children"),
        dash.dependencies.Output("modal-capturing", "is_open"),
        dash.dependencies.Output("modal-capturing-title", "children"),
        dash.dependencies.Output("modal-capturing-body", "children"),
        dash.dependencies.Input("button-capturing-traffic-record", "n_clicks"),
        dash.dependencies.Input('input-radio-mode', 'value'),
        dash.dependencies.State("div-caption-button-capturing-traffic-record", "children"),
        prevent_initial_call=False,
        running=[(dash.dependencies.Output("div-spinner-button-capturing-traffic-record", "style"), {'margin-right': '5px', 'margin-top': '3px'}, {'margin-right': '5px', 'margin-top': '3px', 'display': 'none'})]
    )
    def capturing_traffic_record(button_capturing_traffic_record_n_clicks, input_radio_mode_value, div_caption_button_capturing_traffic_record_children):

        triggered_prop_id = dash.ctx.triggered[0]['prop_id']

        if (triggered_prop_id == 'button-capturing-traffic-record.n_clicks' and button_capturing_traffic_record_n_clicks == 0) or (triggered_prop_id == 'input-radio-mode.value'):

            if input_radio_mode_value == 1:
                
                try:

                    result = subprocess.run(["systemctl", "is-active", 'flownix-collector'], capture_output=True)

                    if result.returncode == 0:
                        return 'Stop capturing', False, '', ''
                    else:
                        return 'Start capturing', False, '', ''
                    
                except subprocess.CalledProcessError as e:
                    return 'Error', True, 'flownix-collector', f'Failed to get status of flownix-collector: {e}'
                
            elif input_radio_mode_value == 2:

                try:

                    result = subprocess.run(["systemctl", "is-active", 'flownix-receiver'], capture_output=True)

                    if result.returncode == 0:
                        return 'Stop capturing', False, '', ''
                    else:
                        return 'Start capturing', False, '', ''
                    
                except subprocess.CalledProcessError as e:
                    return 'Error', True, 'flownix-receiver', f'Failed to get status of flownix-receiver: {e}'

        if triggered_prop_id == 'button-capturing-traffic-record.n_clicks' and div_caption_button_capturing_traffic_record_children == 'Stop capturing':

            if input_radio_mode_value == 1:

                try:
                    subprocess.run(
                        ["systemctl", "stop", 'flownix-collector'],
                        check=True
                    )
                    print(f"flownix-collector stopped successfully.")
                    return 'Start capturing', True, 'flownix-collector', f'flownix-collector stopped successfully.'
                except subprocess.CalledProcessError as e:
                    print(f"Failed to stop flownix-collector: {e}")
                    return 'Stop capturing', True, 'flownix-collector', f'Failed to stop flownix-collector: {e}'
                
            elif input_radio_mode_value == 2:

                try:
                    subprocess.run(
                        ["systemctl", "stop", 'flownix-receiver'],
                        check=True
                    )
                    print(f"flownix-receiver stopped successfully.")
                    return 'Start capturing', True, 'flownix-receiver', f'flownix-receiver stopped successfully.'
                except subprocess.CalledProcessError as e:
                    print(f"Failed to stop flownix-collector: {e}")
                    return 'Stop capturing', True, 'flownix-receiver', f'Failed to stop flownix-receiver: {e}'

        elif triggered_prop_id == 'button-capturing-traffic-record.n_clicks' and div_caption_button_capturing_traffic_record_children == 'Start capturing':

            if input_radio_mode_value == 1:

                try:
                    subprocess.run(
                        ["systemctl", "start", f"flownix-collector"],
                        check=True
                    )
                    print(f"flownix-collector")
                    print(f"Service started successfully")
                    return 'Stop capturing', True, 'flownix-collector', f'Service started successfully'
                except subprocess.CalledProcessError as e:
                    print(f"Failed to start flownix-collector: {e}")
                    return 'Start capturing', True, 'flownix-collector', f'Failed to start flownix-collector: {e}'
                
            elif input_radio_mode_value == 2:

                try:
                    subprocess.run(
                        ["systemctl", "start", f"flownix-receiver"],
                        check=True
                    )
                    print(f"flownix-receiver")
                    print(f"Service started successfully")
                    return 'Stop capturing', True, 'flownix-receiver', f'Service started successfully'
                except subprocess.CalledProcessError as e:
                    print(f"Failed to start flownix-receiver: {e}")
                    return 'Start capturing', True, 'flownix-receiver', f'Failed to start flownix-receiver: {e}'

    @app.callback(
        
        dash.dependencies.Output('input-radio-mode', 'options'),
        dash.dependencies.Output('input-radio-mode', 'value'),
        dash.dependencies.Input('input-radio-mode', 'value'),
        prevent_initial_call=False,
    )
    def toggle_switch(input_radio_mode_value):

        if config["receiver"]["receiver"]:

            return [
                {'label': 'Local', 'value': 1},
                {'label': 'Receiver', 'value': 2, 'disabled': False}
            ], dash.no_update
        
        else:

            return [
                {'label': 'Local', 'value': 1},
                {'label': 'Receiver', 'value': 2, 'disabled': True}
            ], 1

    return app

def main():

    global arg
    arg = parse_arg()

    global config
    config = load_config()

    global app
    app = create_dash_app()

    app.run(debug=True, host=config["dashboard"]["ip"], port=config["dashboard"]["port"])

# Function Declaration -- End

# Global Variable -- Start


# Global Variable -- End

if __name__ == "__main__":

    main()
