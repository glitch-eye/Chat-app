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
from urllib.parse import unquote

from daemon.weaprous import WeApRous

PORT = 8000
app = WeApRous()

# ===== In-memory state =====
PEER_TRACKER = {}      # {peer_id: {ip, port, nick, last_seen}}
CHANNEL_STORE = {}     # {channel_name: set(peer_ids)}
USER_SESSIONS = {}     # {username: {login_time, authenticated}}
PEER_TTL = 60

# ===== Helpers: parse + set response (MUTATION-STYLE) =====
def parse_form_data(body_bytes):
    """Parse application/x-www-form-urlencoded into dict."""
    if not body_bytes:
        return {}
    try:
        s = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return {}
    out = {}
    for pair in s.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[unquote(k)] = unquote(v)
    return out

def parse_cookies(cookie_str):
    cookies = {}
    if not cookie_str or not isinstance(cookie_str, str):
        return cookies
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def _set_html(resp, content_bytes, status=200, cookies=None):
    """Set HTML response (mutation-style, no return)."""
    if isinstance(content_bytes, str):
        content_bytes = content_bytes.encode("utf-8")
    resp.status_code = status
    resp.reason = "OK" if status == 200 else ("Unauthorized" if status == 401 else "Error")
    resp._content = content_bytes
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Length"] = str(len(content_bytes))
    if cookies:
        for k, v in cookies.items():
            resp.cookies[k] = v

def _set_json(resp, payload, status=200, cookies=None):
    """Set JSON response (mutation-style, no return)."""
    body = json.dumps(payload).encode("utf-8")
    resp.status_code = status
    resp.reason = "OK" if status == 200 else "Error"
    resp._content = body
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Length"] = str(len(body))
    if cookies:
        for k, v in cookies.items():
            resp.cookies[k] = v

def _load_www(filename, fallback=b"<h1>Error</h1>"):
    """Load HTML file from www directory."""
    try:
        with open(f"www/{filename}", "rb") as f:
            return f.read()
    except Exception as e:
        print(f"[_load_www] Error loading {filename}: {e}")
        return fallback

# ===== Pages (GET) =====
@app.route("/login", methods=["GET"])
def login_page(req, resp, adapter):
    """Serve login HTML page."""
    html = _load_www("login.html", b"<h1>Login</h1>")
    _set_html(resp, html, status=200)
    print("[GET /login] Serving login page")

@app.route("/submit-info", methods=["GET"])
def submit_info_page(req, resp, adapter):
    """Serve peer registration HTML page."""
    html = _load_www("submit-info.html", b"<h1>Submit Peer</h1>")
    _set_html(resp, html, status=200)
    print("[GET /submit-info] Serving peer registration page")

# ===== Task 1A: POST /login (authenticate) =====
@app.route("/login", methods=["POST"])
def login(req, resp, adapter):
    """
    Authenticate user with username/password.
    On success: Set auth=true cookie and serve index.html
    On failure: Serve 401 unauthorize.html
    """
    form = parse_form_data(getattr(req, "body", b"") or b"")
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()

    print(f"[POST /login] Attempt: username='{username}'")

    if username == "admin" and password == "password":
        USER_SESSIONS[username] = {"login_time": time.time(), "authenticated": True}
        html = _load_www("index.html", b"<h1>Login Success - Welcome!</h1>")
        _set_html(resp, html, status=200, cookies={"auth": "true"})
        print(f"[POST /login] ✓ Success for: {username}")
    else:
        html = _load_www("unauthorize.html", b"<h1>401 Unauthorized</h1>")
        _set_html(resp, html, status=401)
        print(f"[POST /login] ✗ Failed for: {username}")

# ===== Task 1B: GET / (guarded by auth cookie) =====
@app.route("/", methods=["GET"])
@app.route("/index", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index(req, resp, adapter):
    # req.cookies is a STRING, not dict
    cookie_str = getattr(req, "cookies", "") or ""
    cookies = parse_cookies(cookie_str)
    
    print(f"[GET /index] Cookie string: '{cookie_str}' → Parsed: {cookies}")
    
    if cookies.get("auth") == "true":
        html = _load_www("index.html", b"<h1>Welcome</h1>")
        _set_html(resp, html, status=200)
        print("[GET /index] ✓ Authorized access")
    else:
        html = _load_www("unauthorize.html", b"<h1>401 Unauthorized</h1>")
        _set_html(resp, html, status=401)
        print("[GET /index] ✗ Unauthorized access")

# ===== Task 2: POST /submit-info (register peer) =====
@app.route("/submit-info", methods=["POST"])
def submit_info(req, resp, adapter):
    form = parse_form_data(getattr(req, "body", b"") or b"")

    # Support both field naming conventions
    ip   = form.get("ip")   or form.get("peer_ip", "")
    port = form.get("port") or form.get("peer_port", "")
    nick = form.get("nick") or form.get("username", "Anonymous")

    ip, port, nick = ip.strip(), port.strip(), nick.strip()
    
    print(f"[POST /submit-info] Received: ip={ip}, port={port}, nick={nick}")
    
    if not ip or not port:
        _set_json(resp, {"status": "error", "message": "Missing ip or port"}, status=400)
        print("[POST /submit-info] ✗ Missing required fields")
        return

    try:
        p = int(port)
    except ValueError:
        _set_json(resp, {"status": "error", "message": "Invalid port number"}, status=400)
        print("[POST /submit-info] ✗ Invalid port")
        return

    peer_id = f"{ip}:{p}"
    PEER_TRACKER[peer_id] = {"ip": ip, "port": p, "nick": nick, "last_seen": time.time()}
    _set_json(resp, {"status": "ok", "peer_id": peer_id, "total_peers": len(PEER_TRACKER)}, status=200)
    print(f"[POST /submit-info] ✓ Registered: {peer_id}")

# ===== Task 2: GET /get-list (get active peers) =====
@app.route("/get-list", methods=["GET"])
def get_list(req, resp, adapter):
    """
    Get list of active peers (last_seen < PEER_TTL).
    Returns: JSON with peers array and count
    """
    now = time.time()
    active = [
        {"ip": v["ip"], "port": v["port"], "nick": v.get("nick", ""), "peer_id": pid}
        for pid, v in PEER_TRACKER.items()
        if now - v["last_seen"] < PEER_TTL
    ]
    _set_json(resp, {"peers": active, "count": len(active)}, status=200)
    print(f"[GET /get-list] Returning {len(active)}/{len(PEER_TRACKER)} active peers")

# ===== Task 2: POST /add-list (channel management) =====
@app.route("/add-list", methods=["POST"])
def add_list(req, resp, adapter):
    """
    Two modes:
    1. Add peer to channel: channel_name + peer_id
    2. Bulk import peers: peers (CSV format)
    """
    form = parse_form_data(getattr(req, "body", b"") or b"")
    channel_name = form.get("channel_name", "").strip()
    peer_id = form.get("peer_id", "").strip()

    # Mode 1: add peer to channel
    if channel_name:
        CHANNEL_STORE.setdefault(channel_name, set())
        if peer_id:
            CHANNEL_STORE[channel_name].add(peer_id)
        _set_json(resp, {"status": "ok", "channel": channel_name, "members": len(CHANNEL_STORE[channel_name])}, status=200)
        print(f"[POST /add-list] ✓ Added '{peer_id}' to channel '{channel_name}'")
        return

    # Mode 2: bulk import peers via "peers" = ip:port:nick,ip:port:nick
    peers_str = form.get("peers", "").strip()
    added = 0
    if peers_str:
        for item in peers_str.split(","):
            parts = item.split(":")
            if len(parts) >= 2:
                ip = parts[0].strip()
                port_str = parts[1].strip()
                nick = parts[2].strip() if len(parts) >= 3 else "Imported"
                try:
                    p = int(port_str)
                except ValueError:
                    continue
                key = f"{ip}:{p}"
                PEER_TRACKER[key] = {"ip": ip, "port": p, "nick": nick, "last_seen": time.time()}
                added += 1
        _set_json(resp, {"status": "ok", "added": added}, status=200)
        print(f"[POST /add-list] ✓ Bulk imported {added} peers")
        return

    _set_json(resp, {"status": "error", "message": "Missing channel_name or peers"}, status=400)
    print("[POST /add-list] ✗ Missing required fields")

# ===== Task 2: POST /connect-peer (get peer info) =====
@app.route("/connect-peer", methods=["POST"])
def connect_peer(req, resp, adapter):
    """
    Get information about a specific peer.
    Accepts: form data (peer_id) or JSON body
    """
    form = parse_form_data(getattr(req, "body", b"") or b"")
    peer_id = form.get("peer_id", "").strip()

    # Try JSON if not in form data
    if not peer_id and getattr(req, "body", b""):
        try:
            j = json.loads(req.body.decode("utf-8", errors="ignore"))
            peer_id = (j.get("peer_id") or "").strip()
        except Exception:
            peer_id = ""

    print(f"[POST /connect-peer] Request for: '{peer_id}'")

    if peer_id and peer_id in PEER_TRACKER:
        _set_json(resp, {"status": "ok", "peer": PEER_TRACKER[peer_id]}, status=200)
        print(f"[POST /connect-peer] ✓ Found: {peer_id}")
    else:
        _set_json(resp, {"status": "error", "message": "Peer not found"}, status=404)
        print(f"[POST /connect-peer] ✗ Not found: {peer_id}")

# ===== ACKs (control plane only) =====
@app.route("/broadcast-peer", methods=["POST"])
def broadcast_peer(req, resp, adapter):
    """Acknowledge broadcast message (tracker control plane)."""
    _set_json(resp, {"status": "ok", "message": "Broadcast acknowledged"}, status=200)
    print("[POST /broadcast-peer] Acknowledged")

@app.route("/send-peer", methods=["POST"])
def send_peer(req, resp, adapter):
    """Acknowledge direct send (tracker control plane)."""
    _set_json(resp, {"status": "ok", "message": "Direct send acknowledged"}, status=200)
    print("[POST /send-peer] Acknowledged")

# ===== Optional: GET /status (system status) =====
@app.route("/status", methods=["GET"])
def status(req, resp, adapter):
    """System status with tracker statistics."""
    now = time.time()
    active = sum(1 for p in PEER_TRACKER.values() if now - p["last_seen"] < PEER_TTL)
    _set_json(resp, {
        "status": "online",
        "total_peers": len(PEER_TRACKER),
        "active_peers": active,
        "channels": len(CHANNEL_STORE),
        "sessions": len(USER_SESSIONS),
        "timestamp": now
    }, status=200)
    print(f"[GET /status] Stats: {active}/{len(PEER_TRACKER)} peers, {len(CHANNEL_STORE)} channels, {len(USER_SESSIONS)} sessions")

# ===== Main =====
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="SampleApp", 
        description="WeApRous Chat Application with Hybrid P2P Architecture"
    )
    parser.add_argument("--server-ip", default="0.0.0.0", help="IP to bind (default: 0.0.0.0)")
    parser.add_argument("--server-port", type=int, default=PORT, help=f"Port to listen (default: {PORT})")
    args = parser.parse_args()
    
    print("=" * 70)
    print("  WeApRous Chat Application - Centralized Tracker Server")
    print("=" * 70)
    print(f"  Address: {args.server_ip}:{args.server_port}")
    print(f"  Peer TTL: {PEER_TTL}s | Auth: admin/password")
    print("=" * 70)
    
    app.prepare_address(args.server_ip, args.server_port)
    app.run()