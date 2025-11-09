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
import os
import json
import socket
import threading # Cần thiết cho cơ chế Lock
import argparse
import uuid # Cần thiết để tạo ID duy nhất
from daemon.backend import SESSION_STORE, CHANNEL_STORE, STATE_LOCK
from daemon.weaprous import WeApRous
from daemon.httpadapter import HttpAdapter, parse_body_params
from urllib.parse import urlparse, parse_qs

# 🟢 Khóa (Lock) để đảm bảo an toàn khi cập nhật trạng thái chung

PORT = 8000  # Default port

app = WeApRous()

PROXY_HOST_URL = "http://app2.local:8080"
BASE_DIR_FOR_HTML = "www"

def get_base_dir():
    """Lấy thư mục gốc (nơi script này đang chạy)"""
    return os.path.dirname(os.path.abspath(__file__))

# -------------------------------------------------------
# LOGIC TẢI VÀ SỬA ĐỔI (CHỈ CHẠY MỘT LẦN KHI STARTUP)
# -------------------------------------------------------

def _load_page_content(filename):
    """Đọc nội dung file HTML từ thư mục www."""
    filepath = os.path.join(get_base_dir(), BASE_DIR_FOR_HTML, filename)
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"[ERROR] File www/{filename} không tìm thấy.")
        return None
    except Exception as e:
        return None

def load_and_modify_html(filename, serverurl):
    """Tải nội dung và sửa đổi liên kết chuyển hướng."""
    content_bytes = _load_page_content(filename)
    
    if content_bytes is None:
        return b"<h1>Error: Content not loaded. Check server logs.</h1>"
    
    # Chuyển đổi sang string để thao tác chuỗi
    original_content_str = content_bytes.decode('utf-8')
    
    # 🔑 THAO TÁC GHÉP CHUỖI VÀ SỬA LỖI CHUYỂN HƯỚNG
    modified_content_str = original_content_str.replace(
        'href="login.html"',
        f'href="{serverurl}/login.html"'
    )
    
    # Trả về dưới dạng bytes để gán trực tiếp vào response.body
    return modified_content_str.encode('utf-8')
# Trong start_sampleapp.py (Sau các định nghĩa STORE)

INDEX_PAGE = _load_page_content("index.html")
LOGIN_PAGE = _load_page_content("login.html")
UNAUTHORIZED_PAGE = _load_page_content("unauthorize.html")


def check_authentication(request, response, adapter):
    """Kiểm tra session_id trong Cookie và trả về username."""
    cookies = request.headers.get("Set-Cookie")
    if cookies is None:
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False
        return None
    session_id = cookies.get('session_id')

    if session_id is None:
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False
        return None
    
    with STATE_LOCK:
        user_session = SESSION_STORE.get(session_id)

    if not user_session:
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False
        return None
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

    return user_session['username']

@app.route('/', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    print("-------------------------------------")
    check_authentication(request, response, adapter)
        


@app.route('/login', methods=['POST'])
def login_route(request, response, adapter):
    """
    TASK 1A (Mới): Xử lý POST /login (Tạo và Gửi Session ID)
    """
    body_params = parse_body_params(request.body)
    username = body_params.get('username')
    password = body_params.get('password')
    
    # Kiểm tra mật khẩu (Dummy check)
    if username == 'admin' and password == 'password':
        
        # 1. 🟢 TẠO Session ID MỚI VÀ DUY NHẤT
        session_id = str(uuid.uuid4())
        
        with STATE_LOCK:
            SESSION_STORE[session_id] = {
                'username': username,
                'ip': None,           # Sẽ được set bởi /submit-info
                'p2p_port': None,     # Sẽ được set bởi /submit-info
                'channels': [],
                'status': 'offline'
            }
        
        # HttpOnly ngăn chặn XSS đọc cookie, Max-Age là 1 giờ (3600 giây)
        session_cookie = f"sessionid={session_id}" 
        # response.headers['Set-Cookie'] = session_cookie
        request.prepare_cookies(session_cookie)
        response.status_code = 200
        response.reason = "OK"
        request.headers["authorization"] = True
        
        print(f"[AUTH] User {username} logged in. Session ID: {session_id}")
    else:
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False

@app.route('/submit-info', methods=['POST'])
def submit_info_route(request, response, adapter):
    """
    Peer Registration: Cập nhật IP và P2P Port của Peer vào Tracker.
    """
    session_id = request.cookies.get('session_id')
    
    if check_authentication(request, response, adapter) is None:
        return 
    

    body_params = parse_body_params(request.body)
    ip = body_params.get('ip')
    p2p_port = body_params.get('p2p_port')

    if not ip or not p2p_port:
        response.status_code = 400
        response.reason = b'{"Missing IP or P2P port in body"}'
        response.headers['Content-Type'] = 'application/json'
        return

    with STATE_LOCK:
        # 1. Cập nhật thông tin P2P
        SESSION_STORE[session_id]['ip'] = ip
        try:
            SESSION_STORE[session_id]['p2p_port'] = int(p2p_port)
        except ValueError:
            response.status_code = 400
            response.reason = b'{"p2p_port must be an integer"}'
            response.headers['Content-Type'] = 'application/json'
            return
            
        # 2. Đặt trạng thái Online
        SESSION_STORE[session_id]['status'] = 'online'
        
    
    response.status_code = 200
    response.body = json.dumps({
        "status": "info updated", 
        "p2p_address": f"{ip}:{p2p_port}"
    }).encode('utf-8')
    response.headers['Content-Type'] = 'application/json'

@app.route('/add-list', methods=['POST'])
def add_list_route(request, response, adapter):
    """
    Channel Listing/Join: Tham gia/Tạo một Kênh.
    """
    session_id = request.cookies.get('session_id')
    if check_authentication(request, response, adapter) is None:
        return 
    
    body_params = parse_body_params(request.body)
    channel_name = body_params.get('channel_name')
    
    if not channel_name:
        response.status_code = 400
        response.body = b'{"error": "Missing channel_name in body"}'
        response.headers['Content-Type'] = 'application/json'
        return

    with STATE_LOCK:
        # 1. Thêm Channel nếu chưa tồn tại
        if channel_name not in CHANNEL_STORE:
            CHANNEL_STORE[channel_name] = set()
            
        # 2. Thêm Peer vào CHANNEL_STORE
        CHANNEL_STORE[channel_name].add(session_id)
        
        # 3. Cập nhật danh sách kênh của Peer
        if channel_name not in SESSION_STORE[session_id].get('channels', []):
            SESSION_STORE[session_id].setdefault('channels', []).append(channel_name)
    
    response.status_code = 200
    response.body = json.dumps({"status": f"Joined channel {channel_name}", "channel": channel_name}).encode('utf-8')
    response.headers['Content-Type'] = 'application/json'

@app.route('/get-list', methods=['GET'])
def get_list_route(request, response, adapter):
    """
    Peer Discovery: Trả về danh sách Peers (IP:Port P2P) trong một kênh.
    
    Yêu cầu query param: ?channel=<channel_name>
    """
    if check_authentication(request, response, adapter) is None:
        return 
    
    # Giả định request.url_params chứa query parameters (ví dụ: ?channel=...)
    channel_name = request.url_params.get('channel') if hasattr(request, 'url_params') else None
    
    if not channel_name:
        response.status_code = 400
        response.body = b'{"error": "Missing channel query parameter"}'
        response.headers['Content-Type'] = 'application/json'
        return

    peers_data = []
    with STATE_LOCK:
        target_sessions = CHANNEL_STORE.get(channel_name)
        
        if not target_sessions:
            response.status_code = 404
            response.body = b'{"error": "Channel not found"}'
            response.headers['Content-Type'] = 'application/json'
            return

        for sid in target_sessions:
            peer = SESSION_STORE.get(sid)
            # Chỉ liệt kê các peers đã đăng ký thông tin P2P và đang online
            if peer and peer.get('ip') and peer.get('p2p_port') and peer.get('status') == 'online':
                peers_data.append({
                    "username": peer['username'],
                    "ip": peer['ip'],
                    "port": peer['p2p_port'],
                    "session_id": sid
                })

    response.status_code = 200
    response.body = json.dumps({"channel": channel_name, "peers": peers_data}).encode('utf-8')
    response.headers['Content-Type'] = 'application/json'

@app.route('/connect-peer', methods=['GET'])
def connect_peer_route(request, response, adapter):
    """
    Lấy thông tin P2P của một Peer cụ thể bằng Session ID.
    
    Yêu cầu query param: ?session_id=<target_session_id>
    """
    if check_authentication(request, response, adapter) is None:
        return 
    
    # Giả định request.url_params chứa query parameters (ví dụ: ?session_id=...)
    target_sid = request.url_params.get('session_id') if hasattr(request, 'url_params') else None
    
    if not target_sid:
        response.status_code = 400
        response.body = b'{"error": "Missing session_id query parameter"}'
        response.headers['Content-Type'] = 'application/json'
        return

    with STATE_LOCK:
        peer = SESSION_STORE.get(target_sid)

    if peer and peer.get('ip') and peer.get('p2p_port') and peer.get('status') == 'online':
        response.status_code = 200
        response.body = json.dumps({
            "username": peer['username'],
            "ip": peer['ip'],
            "port": peer['p2p_port']
        }).encode('utf-8')
        response.headers['Content-Type'] = 'application/json'
    else:
        response.status_code = 404
        response.body = b'{"error": "Peer not found or P2P info missing"}'
        response.headers['Content-Type'] = 'application/json'

# =========================================================
# 💬 ROUTE HANDLERS: DUMMY P2P ACKNOWLEDGEMENT
# (Giao tiếp P2P thực sự diễn ra qua Socket trực tiếp)
# =========================================================

@app.route('/broadcast-peer', methods=['POST'])
def broadcast_peer_route(request, response, adapter):
    """Dummy Route: Thông báo Server rằng Client đang broadcast (P2P)."""
    if check_authentication(request, response, adapter) is None:
        return
    
    response.status_code = 200
    response.body = b'{"status": "P2P Broadcast Acknowledged by Control Plane"}'
    response.headers['Content-Type'] = 'application/json'

@app.route('/send-peer', methods=['POST'])
def send_peer_route(request, response, adapter):
    """Dummy Route: Thông báo Server rằng Client đang gửi tin nhắn trực tiếp (P2P)."""
    if check_authentication(request, response, adapter) is None:
        return
    
    response.status_code = 200
    response.body = b'{"status": "P2P Direct Send Acknowledged by Control Plane"}'
    response.headers['Content-Type'] = 'application/json'

@app.route('/hello', methods=['PUT'])
def hello(headers, body):
    """
    Handle greeting via PUT request.

    This route prints a greeting message to the console using the provided headers
    and body.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or message payload.
    """
    print ("[SampleApp] ['PUT'] Hello in {} to {}".format(headers, body))


if __name__ == "__main__":
    # Parse command-line arguments to configure server IP and port
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port

    # Prepare and launch the RESTful application
    app.prepare_address(ip, port)
    
    app.run()