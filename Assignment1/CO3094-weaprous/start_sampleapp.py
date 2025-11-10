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
from daemon.httpadapter import HttpAdapter, parse_body_params
from urllib.parse import urlparse, parse_qs

# 🟢 Khóa (Lock) để đảm bảo an toàn khi cập nhật trạng thái chung

PORT = 8000  # Default port

PORT = 8000
app = WeApRous()

PROXY_HOST_URL = "http://app1.local:8080"
BASE_DIR_FOR_HTML = "www"

def get_session_id_from_request():
    """Trích xuất Session ID từ Header Cookie."""
    # Bạn cần đảm bảo logic phân tích Header Cookie trong lớp Request hoạt động
    # Tên cookie: 'sessionid'
    
    # Giả định: self.request.cookies là một dict/CaseInsensitiveDict chứa cookies đã được phân tích.
    with STATE_LOCK:
        cookies = [x for x in SESSION_STORE.keys()]
        return cookies


def handle_get_peer_list():
    
    # 1. KIỂM TRA XÁC THỰC: Lấy danh sách session_id từ request
    session_id_lst = get_session_id_from_request()
    
    # Kiểm tra tính hợp lệ của danh sách session_id
    if not session_id_lst or not isinstance(session_id_lst, list):
        return []  # Không có session hợp lệ → trả về danh sách rỗng
    
    clean_peer_list = []
    
    # 2. ĐỌNG BỘ TRUY CẬP SESSION_STORE VỚI LOCK
    with STATE_LOCK:
        for session_id in session_id_lst:
            # Kiểm tra xem session_id có tồn tại trong SESSION_STORE không
            if session_id not in SESSION_STORE:
                continue  # Bỏ qua session không hợp lệ
            
            session_data = SESSION_STORE[session_id]
            
            # Trích xuất các trường cần thiết
            username = session_data.get('username')
            ip = session_data.get('ip')
            p2p_port = session_data.get('p2p_port')
            status = session_data.get('status')
            
            # Chỉ thêm vào danh sách nếu các trường bắt buộc tồn tại và hợp lệ
            clean_peer_list.append((username, ip, p2p_port, status))
    
    return clean_peer_list

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
    cookies = request.headers.get("cookie", "")
    if cookies == "":
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False
        return None
    session_id = cookies.split("=",1)[1]
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
@app.route('/favicon.ico', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    print("-------------------------------------")
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/welcome.jpg', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    print("-------------------------------------")
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/welcome.png,ico', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    print("-------------------------------------")
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/login', methods=['GET'])
def login_route(request, response, adapter):
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

def _require_auth(cookies):
    return cookies and cookies.get('auth') == 'true'

# ===== Task 1A: POST /login =====
@app.route('/login', methods=['POST'])
def login(method=None, path=None, headers=None, cookies=None, body=None, form_data=None, **_):
    username = (form_data or {}).get('username', '')
    password = (form_data or {}).get('password', '')
    if username == 'admin' and password == 'password':
        
        # 1. 🟢 TẠO Session ID MỚI VÀ DUY NHẤT
        session_id = str(uuid.uuid4())
        
        with STATE_LOCK:
            SESSION_STORE[session_id] = {
                'username': "temp",
                'ip': None,           # Sẽ được set bởi /submit-info
                'p2p_port': None,     # Sẽ được set bởi /submit-info
                'channels': [],
                'status': 'offline'
            }
        
        # HttpOnly ngăn chặn XSS đọc cookie, Max-Age là 1 giờ (3600 giây)
        session_cookie = f"sessionid={session_id}" 
        # response.headers['Set-Cookie'] = session_cookie
        request.prepare_cookies(session_cookie)
        response.headers["Set-Cookie"] = session_cookie
        response.status_code = 200
        response.reason = "OK"
        request.headers["authorization"] = True
        
        print(f"[AUTH] User {username} logged in. Session ID: {session_id}")
    else:
        response.status_code = 401
        response.reason = "Unauthorized"
        request.headers["authorization"] = False

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
def submit_info_route(request, response, adapter):
    """
    Peer Registration: Cập nhật IP và P2P Port của Peer vào Tracker.
    """
    
    if check_authentication(request, response, adapter) is None:
        return 
    session_id = request.cookies.split("=",1)[1]

    body_params = parse_body_params(request.body)
    ip = body_params.get('peer_ip')
    p2p_port = body_params.get('peer_port')
    username = body_params.get('username')

    if not ip or not p2p_port or not username:
        response.status_code = 400
        response.reason = b'{"Missing IP or P2P port in body or username"}'
        response.headers['Content-Type'] = 'application/json'
        return

    with STATE_LOCK:
        # 1. Cập nhật thông tin P2P
        SESSION_STORE[session_id]['ip'] = ip
        SESSION_STORE[session_id]['username'] = username
        try:
            SESSION_STORE[session_id]['p2p_port'] = int(p2p_port)
        except ValueError:
            response.status_code = 400
            response.reason = b'{"p2p_port must be an integer"}'
            response.headers['Content-Type'] = 'application/json'
            return
            
        # 2. Đặt trạng thái Online
        SESSION_STORE[session_id]['status'] = 'online'
        
    response.reason = "OK"
    response.status_code = 200
    print("submit data successfully")
    response.headers['Content-Type'] = 'application/json'

@app.route('/add-list', methods=['POST', 'GET'])
def add_list_route(request, response, adapter):
    """
    Channel Listing/Join: Tham gia/Tạo một Kênh.
    """
    session_id = request.cookies
    if check_authentication(request, response, adapter) is None:
        return
    with STATE_LOCK:
        if SESSION_STORE[session_id]["status"] == "online":
            CHANNEL_STORE["global_chat"][[SESSION_STORE[session_id]["username"]]] =  {}
            CHANNEL_STORE["global_chat"][[SESSION_STORE[session_id]["username"]]]["ip"] = SESSION_STORE[session_id]["ip"]
            CHANNEL_STORE["global_chat"][[SESSION_STORE[session_id]["username"]]]["port"] = SESSION_STORE[session_id]["p2p_port"]


@app.route('/get-list', methods=['GET'])
def get_list_route(request, response, adapter):
    """
    Peer Discovery: Trả về danh sách Peers (IP:Port P2P) trong một kênh.
    
    Yêu cầu query param: ?channel=<channel_name>
    """
    if check_authentication(request, response, adapter) is None:
        return 
@app.route('/list', methods=['GET'])
def get_list_route(request, response, adapter):
    """
    Peer Discovery: Trả về danh sách Peers (IP:Port P2P) trong một kênh.
    
    Yêu cầu query param: ?channel=<channel_name>
    """
    if check_authentication(request, response, adapter) is None:
        return 
    peer_tuples = handle_get_peer_list() # <--- NHẬN DỮ LIỆU TUPLE TẠI ĐÂY
    peer_data_list = []
    for peer in peer_tuples:
        peer_data_list.append({
            "username": peer[0], "ip": peer[1], "p2p_port": peer[2], "status": peer[3]
        })
    
    json_string = json.dumps(peer_data_list)
    response_body_bytes = json_string.encode('utf-8')
    response.headers['Content-Type'] = 'application/json'
    response.setbody(response_body_bytes)
    print(peer_tuples)
    

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