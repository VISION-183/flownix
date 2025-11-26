# Import Module -- Start

import threading
import signal
import queue
import websockets.sync.server
import traceback
import argparse
import sqlite3
import socket
import sys
import os
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
    parser = argparse.ArgumentParser(description="Flownix Receiver", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

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
    print("\nShutdown signal received, flushing DB...")
    shutdown_event.set()
    db_queue.put(None)  # stop DB worker
    server.shutdown()

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

def write_receiver_traffic_table(data, sender_ip, sender_domain, c):

    for key, total_length in data:
        try:
            if key == "sni" or key == "finish":
                continue
            key_src, key_dst, key_etc, key_process, key_parent_process = key.split(" ~~~ ")
            src_domain, src_ip, src_port = key_src.split(" ~~ ")
            dst_domain, dst_ip, dst_port = key_dst.split(" ~~ ")
            interface, direction, network_proto, trans_proto, tos, desc = key_etc.split(" ~~ ")
            process_name, process_cmd, process_arg = key_process.split(" ~~ ")
            parent_process_name, parent_process_cmd, parent_process_arg = key_parent_process.split(" ~~ ")

            # Insert or update in the database
            c.execute('''
                INSERT INTO receiver_traffic (sender_domain, sender_ip, src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg, total_length, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
                ON CONFLICT(sender_domain, sender_ip, src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg)
                DO UPDATE SET total_length = total_length + excluded.total_length, last_updated = datetime('now', 'localtime')
            ''', (sender_domain, sender_ip, src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg, total_length))

        except Exception as e:
            print(f"Exception type: {type(e).__name__}")
            print(f"Exception args: {e.args}")
            print(f"Exception message: {e}")
            traceback.print_exc()

def db_worker():

    """Update the database at regular intervals."""
    conn = sqlite3.connect(config["receiver"]["receiver_db_path"])
    c = conn.cursor()

    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS receiver_traffic (
            sender_domain TEXT,
            sender_ip TEXT,  
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
            PRIMARY KEY (sender_domain, sender_ip, src_domain, src_ip, src_port, dst_domain, dst_ip, dst_port, interface, direction, network_proto, trans_proto, tos, desc, process_name, process_cmd, process_arg, parent_process_name, parent_process_cmd, parent_process_arg)
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
        data, sender_ip, sender_domain = item
        try:
            write_receiver_traffic_table(data, sender_ip, sender_domain, c)  # insert statements
        except Exception as e:
            print("DB write error:", e)
        counter += 1
        db_queue.task_done()

        if counter >= batch_size:
            conn.commit()
            counter = 0

    conn.commit()
    conn.close()

def websocket_handler(websocket):
    for message in websocket:
        data = json.loads(message)
        sender_ip, _ = websocket.remote_address
        print(f"Received from agent: {data}")
        sender_domain = get_domain_by_ip(sender_ip)
        db_queue.put(copy.deepcopy((data, sender_ip, sender_domain)))
        websocket.send(json.dumps({"status": "secure-ok", "echo": data}))

def main():

    global arg
    arg = parse_arg()

    global config
    config = load_config()

    global dns
    dns = {}

    global db_queue
    db_queue = queue.Queue()

    global shutdown_event
    shutdown_event = threading.Event()

    global server

    signal.signal(signal.SIGINT, handle_termination)

    db_thread = threading.Thread(target=db_worker, daemon=False)
    db_thread.start()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=config["receiver"]["receiver_cert_path"], keyfile=config["receiver"]["receiver_key_path"])

    with websockets.sync.server.serve(websocket_handler, config["receiver"]["receiver_wss_ip"], config["receiver"]["receiver_wss_port"], ssl=ssl_context) as server:
        print(f'Server running at wss://{config["receiver"]["receiver_wss_ip"]}:{config["receiver"]["receiver_wss_port"]}')
        server.serve_forever()
        
    db_thread.join()
    print("Server shutdown complete.")

# Function Declaration -- End

# Global Variable -- Start


# Global Variable -- End

if __name__ == "__main__":

    main()