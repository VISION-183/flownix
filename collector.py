# Import Module -- Start

import threading
import queue
import signal
import subprocess
import sys
import os
import re
import time
import sqlite3
import socket
import argparse
import collections
import traceback
import websockets.sync.client
import ssl
import json
import pathlib
import copy

# Import Module -- End

# Function Declaration -- Start

def get_runtime_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS  # PyInstaller temp folder
    return os.path.dirname(os.path.abspath(__file__))  # Script folder

def parse_arg():

    # Create the parser object
    parser = argparse.ArgumentParser(description="Flowix Collector", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

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

# catch Ctrl+C
def handle_termination(signum, frame):
    print("\nShutdown signal received ...")
    shutdown_event.set()
    db_queue.put(None)  # stop DB worker

def initialize_websocket():

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    try:

        ssl_context.load_verify_locations(cafile=config["collector"]["sender_cert_path"])

    except FileNotFoundError:
        print("'sender_cert_path' not found:", config["collector"]["sender_cert_path"])
    except ssl.SSLError as e:
        print("'sender_cert_path' SSL error loading certificate:", e)

    ssl_context.check_hostname = False      # disable hostname check (since self-signed CN may not match IP)
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    while not shutdown_event.is_set():
        try:
           with websockets.sync.client.connect(f'wss://{config["collector"]["sender_wss_ip"]}:{config["collector"]["sender_wss_port"]}', ssl=ssl_context, open_timeout=5, close_timeout=5) as ws:

                print(f'Connected to wss://{config["collector"]["sender_wss_ip"]}:{config["collector"]["sender_wss_port"]}.')

                while not shutdown_event.is_set():  # inner send/receive loop
                    try:
                        data = data_queue.get(timeout=1)
                        ws.send(json.dumps(data))
                        print(f"Sent: {data}")

                        reply = ws.recv()
                        print(f"Server replied: {reply}")

                        data_queue.task_done()

                    except queue.Empty:
                        continue  # no data, check shutdown_event again

                    except websockets.exceptions.ConnectionClosedError as e:
                        print(f"WebSocket connection closed: {e}, reconnecting...")
                        print(f"Exception type: {type(e).__name__}")
                        print(f"Exception args: {e.args}")
                        print(f"Exception message: {e}")
                        traceback.print_exc()
                        time.sleep(5)
                        break  # break inner loop to reconnect

                    except Exception as e:
                        print(f"Unexpected error during send/recv: {e}")
                        print(f"Exception type: {type(e).__name__}")
                        print(f"Exception args: {e.args}")
                        print(f"Exception message: {e}")
                        traceback.print_exc()

        except (OSError, websockets.exceptions.InvalidHandshake, ConnectionRefusedError) as e:
            if shutdown_event.is_set():
                break
            print(f"Could not connect to server: {e}, retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"Exception type: {type(e).__name__}")
            print(f"Exception args: {e.args}")
            print(f"Exception message: {e}")
            traceback.print_exc()

def declare_regex_pattern():

    pattern = {
        'prefix': re.compile(r"^(?P<interface>\S+)\s(?P<direction>In|Out)\s(?P<network_proto>[^,\r\n\t\f\v ]+)"),
        'tos': re.compile(r"tos\s(\S+)\,"),
        'trans_proto': re.compile(r"proto\s(\S+)\s"),
        'length': re.compile(r"length\s(\d+)"),
        'ip': re.compile(r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s>\s(?P<dst_ip>\d+\.\d+\.\d+\.\d+):"),
        'arp_req': re.compile(r"who-has\s(?P<target_ip>\d+\.\d+\.\d+\.\d+)\stell\s(?P<src_ip>\d+\.\d+\.\d+\.\d+)\,"),
        'arp_rep': re.compile(r"Reply\s(?P<target_ip>\d+\.\d+\.\d+\.\d+)\sis-at\s(?P<target_mac>[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})\,"),
        'ip_port': re.compile(r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s>\s(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):"),
        'ip_port_flag': re.compile(r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s>\s(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\sFlags\s\[(?P<flag>[^\]]+)\]"),
        'process': re.compile(r"Process\s\(pid\s(?P<process_pid>\d+)\,\scmd\s(?P<process_cmd>[^,]*)\,\sargs\s(?P<process_arg>[^,]*)\)\,"),
        'parent_process': re.compile(r"ParentProc\s\(pid\s(?P<parent_process_pid>\d+)\,\scmd\s(?P<parent_process_cmd>[^,]*)\,\sargs\s(?P<parent_process_arg>[^,]*)\)"),
        'sni': re.compile(r"SNI=(\S+)\)"),
        'trans_proto_v6': re.compile(r"next-header\s(\S+)\s"),
        'length_v6': re.compile(r"length:\s(\d+)"),
        'ip_v6': re.compile(r"(?P<src_ip>[0-9a-fA-F:]+)\s>\s(?P<dst_ip>[0-9a-fA-F:]+):"),
        'ip_port_v6': re.compile(r"(?P<src_ip>[0-9a-fA-F:]+)\.(?P<src_port>\d+)\s>\s(?P<dst_ip>[0-9a-fA-F:]+)\.(?P<dst_port>\d+):"),
        'ip_port_flag_v6': re.compile(r"(?P<src_ip>[0-9a-fA-F:]+)\.(?P<src_port>\d+)\s>\s(?P<dst_ip>[0-9a-fA-F:]+)\.(?P<dst_port>\d+):\sFlags\s\[(?P<flag>[^\]]+)\]"),
    }

    return pattern

# Helper function to safely extract groups (either named or unnamed)
def get_match_group(pattern, line):
    match = pattern.search(line)
    if match:
        # Check if there are named groups
        if match.groupdict():  # groupdict() will return a non-empty dictionary if named groups exist
            return match.groupdict()  # Return a dictionary of named groups
        else:
            return match.group(1)  # Return a tuple of unnamed groups
    return None  # Return None if no match is found

def get_domain_by_ip(ip):
    """Resolve the domain name (hostname) from an IP address."""
    # Check if the domain is in cache first
    if ip in dns:
        return dns[ip]

    try:
        # Perform reverse DNS lookup to get the hostname for the given IP address
        hostname, _, _ = socket.gethostbyaddr(ip)
        dns[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror):
        # If DNS lookup fails, return the IP as is and cache it
        dns[ip] = 'None'
        return 'None'

# Function to load DNS cache from the database
def read_dns_table():

    """Load DNS cache from the database into the global dns dictionary."""
    conn = sqlite3.connect(config["collector"]["local_db_path"])
    c = conn.cursor()

    # Select all entries from the dns table
    c.execute("SELECT ip, domain FROM dns")
    rows = c.fetchall()

    # Populate the dns dictionary with data from the database
    for row in rows:
        ip, domain = row
        dns[ip] = domain  # Store in the global cache

    conn.close()

def write_dns_table():

    """Write or update the DNS cache to the database."""
    conn = sqlite3.connect(config["collector"]["local_db_path"])
    c = conn.cursor()

    # Create the dns table
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns (
            ip TEXT PRIMARY KEY,
            domain TEXT
        )
    ''')

    conn.commit()

    # Iterate through the DNS cache and update or insert each record
    for ip, domain in dns.items():
        c.execute('''
            INSERT INTO dns (ip, domain)
            VALUES (?, ?)
            ON CONFLICT(ip)
            DO UPDATE SET domain = excluded.domain
        ''', (ip, domain))

    conn.commit()
    conn.close()

def write_traffic_table(length_sums, tcp_session, c):

    items_to_process = list(length_sums.items())

    for tcp_session_key, session_data in tcp_session.items():
        if "key" in session_data:
            items_to_process.extend(list(session_data["key"].items()))

    if config["collector"]["remote_forwarding"]:
        data_queue.put(copy.deepcopy(items_to_process))

    for key, total_length in items_to_process:
        try:
            key_src, key_dst, key_etc, key_process, key_parent_process = key.split(" ~~~ ")
            src_domain, src_ip, src_port = key_src.split(" ~~ ")
            dst_domain, dst_ip, dst_port = key_dst.split(" ~~ ")
            interface, direction, network_proto, trans_proto, tos, desc = key_etc.split(" ~~ ")
            process_name, process_cmd, process_arg = key_process.split(" ~~ ")
            parent_process_name, parent_process_cmd, parent_process_arg = key_parent_process.split(" ~~ ")

            # Insert or update in the database
            c.execute('''
                INSERT INTO traffic (src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg, total_length, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
                ON CONFLICT(src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg)
                DO UPDATE SET total_length = total_length + excluded.total_length, last_updated = datetime('now', 'localtime')
            ''', (src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg, total_length))

        except Exception as e:
            print(f"Exception type: {type(e).__name__}")
            print(f"Exception args: {e.args}")
            print(f"Exception message: {e}")
            traceback.print_exc()

def initialize_parsing():

    length_sums = collections.defaultdict(int)
    tcp_session = collections.defaultdict(lambda: collections.defaultdict(dict))

    command = [os.path.join(get_runtime_path(), "assets/ptcpdump"), "-i", "any", "--oneline", "-n", "-t", "-v"]

    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)

    try:
        while not shutdown_event.is_set():
            start_time = time.time()
            for line in process.stdout:
                # print(f"Captured packet: {line.strip()}")
                # print(line.split(' ')[2])
                # start_time_test = time.time()
                prefix = get_match_group(regex_pattern['prefix'], line)

                if not prefix:
                    pass
                    # print(f"Captured unprefixed packet: {line.strip()}")

                else:

                    network_proto = prefix['network_proto']
                    interface = prefix['interface']
                    direction = prefix['direction']
                    # print(time.time() - start_time_test)
                    # print(prefix['network_proto'])
                    if network_proto == "IP":

                        tos = get_match_group(regex_pattern['tos'], line)
                        trans_proto = get_match_group(regex_pattern['trans_proto'], line)
                        length = get_match_group(regex_pattern['length'], line)

                        if trans_proto == "TCP":

                            ip_port_flag = get_match_group(regex_pattern['ip_port_flag'], line)

                            if not ip_port_flag:

                                print(f"Captured IP-TCP packet without ip_port_flag pattern: {line.strip()}")

                            else:

                                src_ip = ip_port_flag['src_ip']
                                src_port = ip_port_flag['src_port']
                                dst_ip = ip_port_flag['dst_ip']
                                dst_port = ip_port_flag['dst_port']

                                flag = ip_port_flag['flag']

                                process_info = get_match_group(regex_pattern['process'], line)
                                parent_process_info = get_match_group(regex_pattern['parent_process'], line)

                                if process_info:

                                    process_cmd = process_info['process_cmd']
                                    process_arg = process_info['process_arg']

                                    if "/" in process_info['process_cmd']:
                                        process_name = process_info['process_cmd'].split("/")[-1]
                                    else:
                                        process_name = process_info['process_cmd']
                                else:
                                    process_name = process_cmd = process_arg = 'None'

                                if parent_process_info:

                                    parent_process_cmd = parent_process_info['parent_process_cmd']
                                    parent_process_arg = parent_process_info['parent_process_arg']

                                    if "/" in parent_process_info['parent_process_cmd']:
                                        parent_process_name = parent_process_info['parent_process_cmd'].split("/")[-1]
                                    else:
                                        parent_process_name = parent_process_info['parent_process_cmd']
                                else:
                                    parent_process_name = parent_process_cmd = parent_process_arg = 'None'


                                src_domain = get_domain_by_ip(ip_port_flag['src_ip'])
                                dst_domain = get_domain_by_ip(ip_port_flag['dst_ip'])

                                sni = get_match_group(regex_pattern['sni'], line)

                                if sni:

                                    desc = f"sni: {sni}"

                                else:

                                    desc = 'None'

                        elif trans_proto == "UDP":

                            ip_port = get_match_group(regex_pattern['ip_port'], line)

                            src_ip = ip_port['src_ip']
                            src_port = ip_port['src_port']
                            dst_ip = ip_port['dst_ip']
                            dst_port = ip_port['dst_port']

                            process_info = get_match_group(regex_pattern['process'], line)
                            parent_process_info = get_match_group(regex_pattern['parent_process'], line)

                            if process_info:

                                process_cmd = process_info['process_cmd']
                                process_arg = process_info['process_arg']

                                if "/" in process_info['process_cmd']:
                                    process_name = process_info['process_cmd'].split("/")[-1]
                                else:
                                    process_name = process_info['process_cmd']
                            else:
                                process_name = process_cmd = process_arg = 'None'

                            if parent_process_info:

                                parent_process_cmd = parent_process_info['parent_process_cmd']
                                parent_process_arg = parent_process_info['parent_process_arg']

                                if "/" in parent_process_info['parent_process_cmd']:
                                    parent_process_name = parent_process_info['parent_process_cmd'].split("/")[-1]
                                else:
                                    parent_process_name = parent_process_info['parent_process_cmd']
                            else:
                                parent_process_name = parent_process_cmd = parent_process_arg = 'None'


                            src_domain = get_domain_by_ip(ip_port['src_ip'])
                            dst_domain = get_domain_by_ip(ip_port['dst_ip'])

                            desc = 'None'
                        
                        elif trans_proto == "ICMPv4":

                            ip = get_match_group(regex_pattern['ip'], line)

                            src_ip = ip['src_ip']
                            dst_ip = ip['dst_ip']

                            src_domain = get_domain_by_ip(ip['src_ip'])
                            dst_domain = get_domain_by_ip(ip['dst_ip'])

                            src_port = dst_port = process_name = process_cmd = process_arg = parent_process_name = parent_process_cmd = parent_process_arg = desc = 'None'
                        
                        else:

                            print(f"Captured unparsed: {line.strip()}")

                    elif network_proto == "IP6":

                        trans_proto = get_match_group(regex_pattern['trans_proto_v6'], line)
                        length = get_match_group(regex_pattern['length_v6'], line)

                        if trans_proto == "TCP":

                            ip_port_flag = get_match_group(regex_pattern['ip_port_flag_v6'], line)

                            if not ip_port_flag:

                                print(f"Captured IP-TCP packet without ip_port_flag_v6 pattern: {line.strip()}")

                            else:

                                src_ip = ip_port_flag['src_ip']
                                src_port = ip_port_flag['src_port']
                                dst_ip = ip_port_flag['dst_ip']
                                dst_port = ip_port_flag['dst_port']

                                flag = ip_port_flag['flag']

                                process_info = get_match_group(regex_pattern['process'], line)
                                parent_process_info = get_match_group(regex_pattern['parent_process'], line)

                                if process_info:

                                    process_cmd = process_info['process_cmd']
                                    process_arg = process_info['process_arg']

                                    if "/" in process_info['process_cmd']:
                                        process_name = process_info['process_cmd'].split("/")[-1]
                                    else:
                                        process_name = process_info['process_cmd']
                                else:
                                    process_name = process_cmd = process_arg = 'None'

                                if parent_process_info:

                                    parent_process_cmd = parent_process_info['parent_process_cmd']
                                    parent_process_arg = parent_process_info['parent_process_arg']

                                    if "/" in parent_process_info['parent_process_cmd']:
                                        parent_process_name = parent_process_info['parent_process_cmd'].split("/")[-1]
                                    else:
                                        parent_process_name = parent_process_info['parent_process_cmd']
                                else:
                                    parent_process_name = parent_process_cmd = parent_process_arg = 'None'


                                src_domain = get_domain_by_ip(ip_port_flag['src_ip'])
                                dst_domain = get_domain_by_ip(ip_port_flag['dst_ip'])

                                sni = get_match_group(regex_pattern['sni'], line)

                                if sni:

                                    desc = f"sni: {sni}"

                                else:

                                    tos = desc = 'None'

                        elif trans_proto == "UDP":

                            ip_port = get_match_group(regex_pattern['ip_port_v6'], line)

                            src_ip = ip_port['src_ip']
                            src_port = ip_port['src_port']
                            dst_ip = ip_port['dst_ip']
                            dst_port = ip_port['dst_port']

                            process_info = get_match_group(regex_pattern['process'], line)
                            parent_process_info = get_match_group(regex_pattern['parent_process'], line)

                            if process_info:

                                process_cmd = process_info['process_cmd']
                                process_arg = process_info['process_arg']

                                if "/" in process_info['process_cmd']:
                                    process_name = process_info['process_cmd'].split("/")[-1]
                                else:
                                    process_name = process_info['process_cmd']
                            else:
                                process_name = process_cmd = process_arg = 'None'

                            if parent_process_info:

                                parent_process_cmd = parent_process_info['parent_process_cmd']
                                parent_process_arg = parent_process_info['parent_process_arg']

                                if "/" in parent_process_info['parent_process_cmd']:
                                    parent_process_name = parent_process_info['parent_process_cmd'].split("/")[-1]
                                else:
                                    parent_process_name = parent_process_info['parent_process_cmd']
                            else:
                                parent_process_name = parent_process_cmd = parent_process_arg = 'None'


                            src_domain = get_domain_by_ip(ip_port['src_ip'])
                            dst_domain = get_domain_by_ip(ip_port['dst_ip'])

                            tos = desc = 'None'
                        
                        elif trans_proto == "ICMPv6":

                            ip = get_match_group(regex_pattern['ip_v6'], line)

                            src_ip = ip['src_ip']
                            dst_ip = ip['dst_ip']

                            src_domain = get_domain_by_ip(ip['src_ip'])
                            dst_domain = get_domain_by_ip(ip['dst_ip'])

                            tos = src_port = dst_port = process_name = process_cmd = process_arg = parent_process_name = parent_process_cmd = parent_process_arg = desc = 'None'
                        
                        else:

                            print(f"Captured unparsed: {line.strip()}")

                    elif network_proto == "ARP":

                        arp_req_info = get_match_group(regex_pattern['arp_req'], line)
                        if arp_req_info:
                            src_ip = arp_req_info['src_ip']
                            src_domain = get_domain_by_ip(src_ip)
                            target_ip = arp_req_info['target_ip']
                            length = get_match_group(regex_pattern['length'], line)
                            desc = f"target_ip: {target_ip}"

                            dst_domain = dst_ip = tos = trans_proto = src_port = dst_port = process_name = process_cmd = process_arg = parent_process_name = parent_process_cmd = parent_process_arg = 'None'


                        else:
                            arp_rep_info = get_match_group(regex_pattern['arp_rep'], line)
                            target_ip = arp_rep_info['target_ip']
                            target_mac = arp_rep_info['target_mac']
                            length = get_match_group(regex_pattern['length'], line)
                            desc = f"target_ip: {target_ip}, target_mac: {target_mac}"

                            src_ip = src_domain = dst_domain = dst_ip = tos = trans_proto = src_port = dst_port = process_name = process_cmd = process_arg = parent_process_name = parent_process_cmd = parent_process_arg = 'None'

                    else:
                        print(f"Captured uncategorized packet: {line.strip()}")

        #            print(src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg)
                    
                    if trans_proto == "TCP":

                        endpoint = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                        tcp_session_key =  f"{endpoint[0][0]} ~~ {endpoint[0][1]} ~~~ {endpoint[1][0]} ~~ {endpoint[1][1]} ~~~ {interface}"

                        if desc.startswith("sni"):
                            tcp_session[tcp_session_key]["info"]["sni"] = desc

                        if "sni" in tcp_session.get(tcp_session_key, {}).get("info", {}):

                            desc = tcp_session[tcp_session_key]["info"]["sni"]
                            key = f"{src_domain} ~~ {src_ip} ~~ {src_port} ~~~ {dst_domain} ~~ {dst_ip} ~~ {dst_port} ~~~ {interface} ~~ {direction} ~~ {network_proto} ~~ {trans_proto} ~~ {tos} ~~ {desc} ~~~ {process_name} ~~ {process_cmd} ~~ {process_arg} ~~~ {parent_process_name} ~~ {parent_process_cmd} ~~ {parent_process_arg}"

                        else:

                            key = f"{src_domain} ~~ {src_ip} ~~ {src_port} ~~~ {dst_domain} ~~ {dst_ip} ~~ {dst_port} ~~~ {interface} ~~ {direction} ~~ {network_proto} ~~ {trans_proto} ~~ {tos} ~~ {desc} ~~~ {process_name} ~~ {process_cmd} ~~ {process_arg} ~~~ {parent_process_name} ~~ {parent_process_cmd} ~~ {parent_process_arg}"

                        if key not in tcp_session[tcp_session_key]["key"]:
                            tcp_session[tcp_session_key]["key"][key] = 0

                        if "finish" not in tcp_session[tcp_session_key]["info"]:
                                tcp_session[tcp_session_key]["info"]["finish"] = 0

                        tcp_session[tcp_session_key]["key"][key] += int(length)

                        if "R" in flag:

                            tcp_session[tcp_session_key].clear()

                        if "F" in flag and tcp_session[tcp_session_key]["info"]["finish"] != 2:

                            tcp_session[tcp_session_key]["info"]["finish"] += 1

                        elif "F" in flag and tcp_session[tcp_session_key]["info"]["finish"] == 2:

                            tcp_session[tcp_session_key].clear()

                    else:
                        key = f"{src_domain} ~~ {src_ip} ~~ {src_port} ~~~ {dst_domain} ~~ {dst_ip} ~~ {dst_port} ~~~ {interface} ~~ {direction} ~~ {network_proto} ~~ {trans_proto} ~~ {tos} ~~ {desc} ~~~ {process_name} ~~ {process_cmd} ~~ {process_arg} ~~~ {parent_process_name} ~~ {parent_process_cmd} ~~ {parent_process_arg}"
                        length_sums[key] += int(length)

                elapsed_time = time.time() - start_time
                if elapsed_time >= 5:
                    break

            db_queue.put((copy.deepcopy(length_sums), copy.deepcopy(tcp_session)))
            length_sums.clear()
            for tcp_session_key, session_data in tcp_session.items():
                if "key" in session_data:
                    session_data["key"].clear()


    except Exception as e:
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception args: {e.args}")
        print(f"Exception message: {e}")
        traceback.print_exc()

    finally:
        process.terminate()
        process.wait()
        for line in process.stderr:
            print(line)
        write_dns_table()

def db_worker():

    """Update the database at regular intervals."""
    conn = sqlite3.connect(config["collector"]["local_db_path"])
    c = conn.cursor()

    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            src_domain TEXT,
            src_ip TEXT,
            src_port TEXT,
            dst_domain TEXT,
            dst_ip TEXT,
            dst_port TEXT,
            interface TEXT,
            direction TEXT,
            network_proto TEXT,
            trans_proto TEXT,
            tos TEXT,
            desc TEXT,
            process_name TEXT,
            process_cmd TEXT,
            process_arg TEXT,
            parent_process_name TEXT,
            parent_process_cmd TEXT,
            parent_process_arg TEXT,
            total_length INTEGER,
            last_updated TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg)
        )
    ''')
    conn.commit()

    conn.execute("PRAGMA journal_mode=WAL;")

    batch_size = 5
    counter = 0

    while True:
        try:
            item = db_queue.get(timeout=1)
        except queue.Empty:
            if shutdown_event.is_set():
                break
            continue

        if item is None:
            break
        length_sums, tcp_session = item
        try:
            write_traffic_table(length_sums, tcp_session, c)  # insert statements
        except Exception as e:
            print("DB write error:", e)
        counter += 1
        db_queue.task_done()

        if counter >= batch_size:
            conn.commit()
            counter = 0

    conn.commit()
    conn.close()

def main():

    global arg
    arg = parse_arg()

    global config
    config = load_config()

    global regex_pattern
    regex_pattern = declare_regex_pattern()
    global dns
    dns = {}

    global shutdown_event
    shutdown_event = threading.Event()

    signal.signal(signal.SIGINT, handle_termination)

    global data_queue
    data_queue = queue.Queue()

    global db_queue
    db_queue = queue.Queue()

    write_dns_table()
    read_dns_table()

    if config["collector"]["remote_forwarding"]:
        ws_thread = threading.Thread(target=initialize_websocket, daemon=False)
    
    db_thread = threading.Thread(target=db_worker, daemon=False)
    parsing_thread = threading.Thread(target=initialize_parsing, daemon=False)

    if config["collector"]["remote_forwarding"]:
        ws_thread.start()
    
    db_thread.start()
    parsing_thread.start()

    if config["collector"]["remote_forwarding"]:
        ws_thread.join()
    
    db_thread.join()
    parsing_thread.join()

# Function Declaration -- End

# Global Variable -- Start


# Global Variable -- End

if __name__ == "__main__":

    main()