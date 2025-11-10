#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the "MIT License Agreement". Please see the LICENSE
# file that should have been included as part of this package.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#


"""
start_sampleapp
~~~~~~~~~~~~~~~~~

This module provides a sample RESTful web application using the WeApRous framework.

It defines basic route handlers and launches a TCP-based backend server to serve
HTTP requests. The application includes a login endpoint and a greeting endpoint,
and can be configured via command-line arguments.
"""

import json
import time
import argparse
from daemon.weaprous import WeApRous

PORT = 8000
app = WeApRous()

# ===== In-memory state =====
PEER_TRACKER = {}      # {peer_id: {ip, port, nick, last_seen}}
CHANNEL_STORE = {}     # {channel_name: set(peer_ids)}
USER_SESSIONS = {}     # {username: {login_time, authenticated}}
PEER_TTL = 60

# ===== Helpers =====
def _json(payload, status=200, cookies=None, headers=None):
    body = json.dumps(payload).encode('utf-8')
    h = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if headers: h.update(headers)
    return {"status": status, "headers": h, "cookies": (cookies or {}), "body": body}

def _html(content, status=200, cookies=None):
    body = content if isinstance(content, bytes) else content.encode('utf-8')
    h = {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body))}
    return {"status": status, "headers": h, "cookies": (cookies or {}), "body": body}

def _load_html(name, fallback=b''):
    try:
        with open(f'www/{name}', 'rb') as f:
            return f.read()
    except:
        return fallback

def _require_auth(cookies):
    return cookies and cookies.get('auth') == 'true'

# ===== Task 1A: POST /login =====
@app.route('/login', methods=['POST'])
def login(method=None, path=None, headers=None, cookies=None, body=None, form_data=None, **_):
    username = (form_data or {}).get('username', '')
    password = (form_data or {}).get('password', '')
    if username == 'admin' and password == 'password':
        USER_SESSIONS[username] = {'login_time': time.time(), 'authenticated': True}
        html = _load_html('index.html', b'<h1>Login Success</h1>')
        return _html(html, status=200, cookies={'auth': 'true'})
    html = _load_html('401.html', b'<h1>401 Unauthorized</h1>')
    return _html(html, status=401)

# ===== Task 1B: GET / =====
@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
@app.route('/index.html', methods=['GET'])
def index(method=None, path=None, headers=None, cookies=None, **_):
    if _require_auth(cookies):
        html = _load_html('index.html', b'<h1>Welcome</h1>')
        return _html(html, status=200)
    html = _load_html('401.html', b'<h1>401 Unauthorized</h1>')
    return _html(html, status=401)

# ===== Task 2: POST /submit-info =====
@app.route('/submit-info', methods=['POST'])
def submit_info(method=None, path=None, headers=None, cookies=None, body=None, form_data=None, **_):
    ip = (form_data or {}).get('ip', '')
    port = (form_data or {}).get('port', '')
    nick = (form_data or {}).get('nick', '')
    if not ip or not port:
        return _json({"status": "error", "message": "Missing ip or port"}, status=400)
    peer_id = f"{ip}:{port}"
    PEER_TRACKER[peer_id] = {"ip": ip, "port": int(port), "nick": nick, "last_seen": time.time()}
    return _json({"status": "ok", "peer_id": peer_id, "total_peers": len(PEER_TRACKER)})

# ===== Task 2: GET /get-list =====
@app.route('/get-list', methods=['GET'])
def get_list(method=None, path=None, headers=None, cookies=None, **_):
    now = time.time()
    active = [
        {"ip": p["ip"], "port": p["port"], "nick": p.get("nick", ""), "peer_id": pid}
        for pid, p in PEER_TRACKER.items()
        if now - p["last_seen"] < PEER_TTL
    ]
    return _json({"peers": active, "count": len(active)})

# ===== Task 2: POST /add-list =====
@app.route('/add-list', methods=['POST'])
def add_list(method=None, path=None, headers=None, cookies=None, body=None, form_data=None, **_):
    channel_name = (form_data or {}).get('channel_name', '')
    peer_id = (form_data or {}).get('peer_id', '')
    if channel_name:
        CHANNEL_STORE.setdefault(channel_name, set())
        if peer_id:
            CHANNEL_STORE[channel_name].add(peer_id)
        return _json({"status": "ok", "channel": channel_name, "members": len(CHANNEL_STORE[channel_name])})
    peers_str = (form_data or {}).get('peers', '')
    added = 0
    if peers_str:
        for item in peers_str.split(','):
            parts = item.split(':')
            if len(parts) >= 2:
                ip, port = parts[0], parts[1]
                nick = parts[2] if len(parts) >= 3 else ''
                key = f"{ip}:{port}"
                PEER_TRACKER[key] = {"ip": ip, "port": int(port), "nick": nick, "last_seen": time.time()}
                added += 1
        return _json({"status": "ok", "added": added})
    return _json({"status": "error", "message": "Missing channel_name or peers"}, status=400)

# ===== Task 2: POST /connect-peer =====
@app.route('/connect-peer', methods=['POST'])
def connect_peer(method=None, path=None, headers=None, cookies=None, body=None, form_data=None, **_):
    peer_id = (form_data or {}).get('peer_id')
    if peer_id is None and body:
        try:
            peer_id = json.loads(body.decode('utf-8')).get('peer_id')
        except:
            peer_id = None
    if peer_id and peer_id in PEER_TRACKER:
        return _json({"status": "ok", "peer": PEER_TRACKER[peer_id]})
    return _json({"status": "error", "message": "Peer not found"}, status=404)

# ===== Task 2: POST /broadcast-peer (ack) =====
@app.route('/broadcast-peer', methods=['POST'])
def broadcast_peer(method=None, path=None, headers=None, cookies=None, **_):
    return _json({"status": "ok", "message": "Broadcast acknowledged"})

# ===== Task 2: POST /send-peer (ack) =====
@app.route('/send-peer', methods=['POST'])
def send_peer(method=None, path=None, headers=None, cookies=None, **_):
    return _json({"status": "ok", "message": "Direct send acknowledged"})

# ===== Optional: /status =====
@app.route('/status', methods=['GET'])
def status(method=None, path=None, **_):
    now = time.time()
    active_peers = sum(1 for p in PEER_TRACKER.values() if now - p["last_seen"] < PEER_TTL)
    return _json({
        "status": "online",
        "total_peers": len(PEER_TRACKER),
        "active_peers": active_peers,
        "channels": len(CHANNEL_STORE),
        "sessions": len(USER_SESSIONS)
    })

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='SampleApp', description='WeApRous sample app')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
    args = parser.parse_args()
    app.prepare_address(args.server_ip, args.server_port)
    app.run()