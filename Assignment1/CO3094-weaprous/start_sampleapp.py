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
"""
import os
import json
import socket
import threading
import argparse
import uuid 
from daemon.backend import SESSION_STORE , STATE_LOCK , CHANNEL_STORE
from daemon.weaprous import WeApRous
from daemon.httpadapter import HttpAdapter, parse_body_params
from urllib.parse import urlparse, parse_qs
import subprocess
import sys
import requests
from daemon.request import Request

# 🟢 Khóa (Lock) để đảm bảo an toàn khi cập nhật trạng thái chung

PORT = 8000  # Default port

app = WeApRous()

# -------------------------------------------------------
# 🌐 WEBRTC SIGNALING GLOBAL STATE
# -------------------------------------------------------
# Khóa (Lock) để bảo vệ dữ liệu signaling khi truy cập đồng thời
WEBRTC_SIGNAL_LOCK = threading.Lock() 

# Lưu trữ dữ liệu Offer/Answer/ICE. Key là username của PEER ĐÍCH
# Ví dụ: Peer A gửi Offer cho Peer B, Offer được lưu trữ dưới key là username của B
WEBRTC_SIGNAL_STORE = {} 

# Cấu trúc: 
# {
#     'peer_b_username': {
#         'offer': <SDP_Object>,
#         'answer': <SDP_Object>,
#         'ice_candidates': [<ICE_Candidate_1>, <ICE_Candidate_2>, ...]
#     },
#     'peer_a_username': {...}
# }

# -------------------------------------------------------
# HÀM TIỆN ÍCH WEBRTC
# -------------------------------------------------------
def send_peer_notification(ip, port, target_username, body_data):
    """
    Thực hiện HTTP POST tới Peer Server để thông báo có tín hiệu P2P mới.
    """
    target_url = f"http://{ip}:{port}/webrtc/initiate" # Route mới trên Peer Server
    
    # Cần dùng thư viện Requests (hoặc Socket thô)
    try:
        # Giả định Peer Server chấp nhận JSON
        # Chúng ta sẽ dùng thư viện requests đơn giản hơn cho việc này
        
        headers = {'Content-Type': 'application/json'}
        response = requests.post(target_url, json=body_data, headers=headers, timeout=5)
        
        if response.status_code == 200:
            print(f"[Tracker -> Peer] Thông báo kết nối thành công tới {target_url}")
            return True
        else:
            print(f"[Tracker -> Peer] Lỗi khi gửi thông báo tới Peer B: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[Tracker -> Peer ERROR] Không thể kết nối tới Peer B ({ip}:{port}): {e}")
        return False
        
    except Exception as e:
        # Nếu thư viện requests không khả dụng, dùng socket thô. (Chúng ta sẽ giả định requests khả dụng cho tiện)
        print(f"[Tracker ERROR] Lỗi không xác định khi gửi thông báo: {e}")
        return False
def get_query_param(request, key):
    """Trích xuất giá trị của một query parameter từ URL."""
    try:
        parsed_url = urlparse(request.path)
        query_params = parse_qs(parsed_url.query)
        # Trả về giá trị đầu tiên (nếu có)
        return query_params.get(key, [None])[0]
    except Exception as e:
        print(f"[ERROR] Could not parse query params: {e}")
        return None


def parse_response(response_data):
    """Phân tích Response bytes thành Status, Headers, và Body."""
    if not response_data:
        return None, None, None, None
    try:
        # Tách Header và Body
        header_body_split = response_data.find(b'\r\n\r\n')
        if header_body_split == -1:
            return 'N/A', b'', {}, b''
        header_bytes = response_data[:header_body_split]
        body_bytes = response_data[header_body_split + 4:]
        
        header_text = header_bytes.decode('utf-8', errors='ignore')
        lines = header_text.split('\r\n')
        
        status_line = lines[0]
        status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else 'N/A'
        
        # Phân tích Headers
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value.strip()
                
        # Trả về status_code (string), header_text (string), headers (dict), body_bytes (bytes)
        return status_code, header_text, headers, body_bytes

    except Exception as e:
        print(f"[ERROR] Lỗi phân tích Response: {e}")
        return 'N/A', b'', {}, b''
# -------------------------------------------------------
# LOGIC TẢI VÀ SỬA ĐỔI (CHỈ CHẠY MỘT LẦN KHI STARTUP)
# -------------------------------------------------------

def check_authentication(request, response, adapter):
    """Kiểm tra session_id trong Cookie và trả về username."""
    cookies = request.headers.get("cookie", "")
    
    # Phân tích cookie: Tìm sessionid=<value>
    session_id = None
    for cookie_pair in cookies.split(';'):
        if cookie_pair.strip().startswith('sessionid='):
            try:
                session_id = cookie_pair.strip().split('=', 1)[1]
            except IndexError:
                session_id = None
            break
            
    if not session_id:
        response.status_code = 401
        response.reason = "Unauthorized (No sessionid cookie)"
        request.headers["authorization"] = False
        return None
    
    with STATE_LOCK:
        user_session = SESSION_STORE.get(session_id)

    if not user_session:
        response.status_code = 401
        response.reason = "Unauthorized (Invalid session ID)"
        request.headers["authorization"] = False
        return None
        
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True
    return user_session['username']
# -------------------------------------------------------
# LOGIC TẢI VÀ SỬA ĐỔI (CHỈ CHẠY MỘT LẦN KHI STARTUP)
# -------------------------------------------------------


# (Phần định nghĩa các hàm khác...)

def start_process(file_name, ip, port, role, sessionid):
    """Khởi chạy một tiến trình Server mới."""
    print(f"[{role}] 🚀 Khởi chạy {file_name} tại {ip}:{port}...")
    
    command = [
        sys.executable,  
        file_name,
        '--server-ip', ip,
        '--server-port', str(port)
    ]
    
    # Chạy ngầm
    process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
    return process


# Đã bỏ hàm get_session_id_from_request vì lỗi logic


def handle_get_peer_list(exception_id = None):
    """
    Trả về danh sách Peers đang online, loại trừ Peer có session_id là exception_id.
    """
    clean_peer_list = []
    
    with STATE_LOCK:
        # Lấy danh sách session_id mà Peer hiện tại đã kết nối tới
        connected_peers = CHANNEL_STORE.get(exception_id, [])
        
        for session_id, session_data in SESSION_STORE.items():
            # 1. Bỏ qua chính Peer hiện tại
            if session_id == exception_id:
                continue 
            
            username = session_data.get('username')
            ip = session_data.get('ip')
            p2p_port = session_data.get('p2p_port')
            status = session_data.get('status')
            
            # 2. Chỉ thêm vào danh sách nếu đã online và có đủ thông tin
            if username and ip and p2p_port and status == 'online':
                # Kiểm tra trạng thái kết nối
                is_connected = session_id in connected_peers
                # Cấu trúc: (username, ip, p2p_port, status, isConnected)
                clean_peer_list.append((username, ip, p2p_port, status, is_connected))
    
    return clean_peer_list

def build_error_response_json_bytes(status_code, message):
    """Tạo body JSON bytes cho phản hồi lỗi."""
    json_string = json.dumps({"message": message})
    return json_string.encode('utf-8')

def set_json_response(resp, data, status_code=200):
    """Thiết lập đối tượng Response (resp) thành JSON hợp lệ."""
    resp.status_code = status_code
    resp.reason = 'OK'
    resp.content_type = 'application/json'
    resp.setbody(json.dumps(data).encode('utf-8'))

def lookup(username):
    """Tìm session_id cho username dựa trên SESSION_STORE."""
    with STATE_LOCK:
        # Duyệt qua tất cả các session để tìm username khớp
        for session_id, session_data in SESSION_STORE.items():
            if session_data.get('username') == username:
                return session_id
    return None


# -------------------------------------------------------
# ROUTE DEFINITION
# -------------------------------------------------------

@app.route('/new_message', methods=['GET'])
def get_new(request, response, adapter):
    
    # Lấy session_id từ cookies
    cookies = request.cookies
    if check_authentication(request, response, adapter) is None:
        return

    session_id = request.cookies.split('=',1)[1]

    # 2. Lấy IP và Port P2P của Peer hiện tại
    with STATE_LOCK:
        session_data = SESSION_STORE.get(session_id)
        if not session_data or session_data.get('status') != 'online':
            response.status_code = 403
            response.setbody(b'{"error": "Peer is not fully online/registered"}')
            response.headers['Content-Type'] = 'application/json'
            return
            
        ip = session_data['ip']
        port = session_data['p2p_port']

    # 3. Xây dựng và Gửi HTTP GET Request đến Peer Server (sử dụng Socket)
    request_headers = {
        "Host": f"{ip}:{port}", # Host phải bao gồm cả Port P2P
        "User-Agent": "Tracker/1.0",
        "Connection": "close"
    }
    
    # 🎯 Endpoint TRONG Peer Server: Cần gọi /messages/new hoặc /new_message
    request_line = f"GET /new_message/ HTTP/1.1\r\n" 
    header_lines = [f"{k}: {v}" for k, v in request_headers.items()]
    request_data = request_line + "\r\n".join(header_lines) + "\r\n\r\n"
    request_data_bytes = request_data.encode('utf-8')

    response_data = b""
    status_code = 503 # Mặc định lỗi
    body_bytes = b'[]' # Mặc định trả về mảng rỗng nếu lỗi

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0) # Tăng timeout nhẹ
            s.connect((ip, port))
            s.sendall(request_data_bytes)
            # Đọc Response
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response_data += chunk

            # SỬA LỖI: parse_response cần response_data là bytes
            status_code_str, _, _, body_bytes_temp = parse_response(response_data)
            
            # Cần chuyển status_code thành int
            try:
                status_code = int(status_code_str)
                if status_code == 200:
                    body_bytes = body_bytes_temp
                else:
                    body_bytes = b'[]' 
            except ValueError:
                 # Lỗi parsing status code
                status_code = 500

    except Exception as e:
        print(f"[Tracker Error] Lỗi kết nối hoặc đọc response từ peer {ip}:{port}: {e}")
        # Giữ status_code là 503 (Service Unavailable)
        response.status_code = 503
        response.setbody(b'{"error": "Could not connect to peer server"}')
        response.headers['Content-Type'] = 'application/json'
        return

    response.status_code = 200 
    response.setbody(body_bytes) 
    response.headers['Content-Type'] = 'application/json'

@app.route('/', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    print("-------------------------------------")
    check_authentication(request, response, adapter)
@app.route('/favicon.ico', methods=['GET'])
def favicon_route(request, response, adapter):
    """
    Xử lý favicon.
    """
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/welcome.jpg', methods=['GET'])
def welcome_jpg_route(request, response, adapter):
    """
    Xử lý welcome.jpg.
    """
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/welcome.png,ico', methods=['GET'])
def welcome_png_ico_route(request, response, adapter):
    """
    Xử lý welcome.png hoặc .ico.
    """
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/login', methods=['GET'])
def login_get_route(request, response, adapter):
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True


# ===== Task 1A: POST /login =====
@app.route('/login', methods=['POST'])
def login_route(request, response, adapter):
    """
    TASK 1A (Mới): Xử lý POST /login (Tạo và Gửi Session ID)
    """
    body_params = parse_body_params(request.body)
    username = body_params.get('username')
    password = body_params.get('password')
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
@app.route('/submit-info', methods=['GET'])
def submit_info_route_get(request, response, adapter):
    """
    Peer Registration: Cập nhật IP và P2P Port của Peer vào Tracker.
    """
    if check_authentication(request, response, adapter) is None:
        return 
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

@app.route('/submit-info', methods=['POST'])
def submit_info_route_post(request, response, adapter):
    """
    Peer Registration: Cập nhật IP và P2P Port của Peer vào Tracker.
    """
    
    if check_authentication(request, response, adapter) is None:
        return 
    
    session_id = request.cookies.split("=",1)[1]

    body_params = parse_body_params(request.body,'json')
    ip = body_params.get('peer_ip')
    p2p_port = body_params.get('peer_port')
    username = body_params.get('username')

    if lookup(username) is not None:
        response.status_code = 400
        response.setbody(b'{"message": "Username have been taken"}')
        response.headers['Content-Type'] = 'application/json'
        return
        
    if not ip or not p2p_port or not username:
        response.status_code = 400
        response.setbody(b'{"message": "Missing IP or P2P port in body or username"}')
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
            response.setbody(b'{"message": "p2p_port must be an integer"}')
            response.headers['Content-Type'] = 'application/json'
            return
            
        # 2. Đặt trạng thái Online
        SESSION_STORE[session_id]['status'] = 'online'
        
    response.reason = "OK"
    response.status_code = 200
    print("submit data successfully")
    response.headers['Content-Type'] = 'application/json'

@app.route('/name', methods=['GET'])
def get_name_route(request, response, adapter):
    """
    Trả về username của phiên hiện tại.
    """
    if check_authentication(request, response, adapter) is None:
        return 
    
    # Lấy session ID một cách an toàn hơn
    try:
        session_id = request.cookies.split('=',1)[1]
    except IndexError:
        # Should be caught by check_authentication, but good practice to handle
        response.status_code = 401
        response.setbody(b'{"message": "Unauthorized"}')
        response.headers['Content-Type'] = 'application/json'
        return

    with STATE_LOCK:
        session_data = SESSION_STORE.get(session_id)
        current_username = session_data["username"] if session_data else "Unknown"

    response.setbody(build_error_response_json_bytes(200, current_username))
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True

# ----------------------------------------end infor -------------------------------------
@app.route('/add-list', methods=['POST', 'GET'])
def add_list_route(request, response, adapter):
    """
    Channel Listing/Join: Tham gia/Tạo một Kênh.
    """
    if check_authentication(request, response, adapter) is None:
        return
        
    cookies = request.cookies
    session_id = cookies.split('=',1)[1]
    
    with STATE_LOCK:
        session_data = SESSION_STORE.get(session_id)
        if not session_data:
            response.status_code = 401
            response.setbody(b'{"message": "Session not found"}')
            response.headers['Content-Type'] = 'application/json'
            return
            
        # Đảm bảo Peer đang online và thêm vào CHANNEL_STORE (logic user)
        if session_data["status"] != "online":
            session_data["status"] = "online"
            
        # Logic này của user chỉ thêm vào global_chat (không liên quan đến CHANNEL_STORE)
        # Giữ nguyên logic khởi động process của Peer Server
        
        username = session_data['username']
        ip = session_data['ip']
        p2p_port = session_data['p2p_port']
    
    # Giả định CHANNEL_STORE["global_chat"] chỉ là một mảng session_id để theo dõi
    # Tôi sẽ bỏ qua việc thêm vào CHANNEL_STORE["global_chat"] vì nó không được dùng
    # cho mục đích kết nối P2P sau này mà chỉ là một biến global không chính xác.
    # Thay vào đó, tập trung vào việc khởi chạy Peer Server
    
    start_process('peer_server.py', ip, p2p_port, f"peer_client {username}", session_id)
    
    response.status_code = 200
    # response.setbody(b'{"message": "Peer server process initiated"}')
    response.headers['Content-Type'] = 'application/json'

# Route /get-list không có logic nên bỏ qua
@app.route('/get-list', methods=['GET'])
def get_list_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return 

@app.route('/list', methods=['GET'])
def get_list_route_v2(request, response, adapter):
    """
    Peer Discovery: Trả về danh sách Peers đang online (và trạng thái kết nối).
    """
    if check_authentication(request, response, adapter) is None:
        return 
        
    session_id = request.cookies.split('=',1)[1]
    
    # Lấy danh sách peers, loại trừ chính Peer đang yêu cầu (exception_id)
    peer_tuples = handle_get_peer_list(session_id)
    peer_data_list = []
    
    # Peer tuple: (username, ip, p2p_port, status, isConnected)
    for peer in peer_tuples:
        peer_data_list.append({
            "username": peer[0], "ip": peer[1], "p2p_port": peer[2], "status": peer[3], "isConnected": peer[4]
        })
    
    json_string = json.dumps(peer_data_list)
    response_body_bytes = json_string.encode('utf-8')
    response.headers['Content-Type'] = 'application/json'
    response.setbody(response_body_bytes)

@app.route('/connect-peer', methods=['POST'])
def connect_peer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return 
    
    body_params = parse_body_params(request.body,'json')
    # t_ip = body_params.get('ip') # Không cần dùng IP/Port của Peer B từ Client
    # t_p2p_port = body_params.get('port') # Không cần dùng IP/Port của Peer B từ Client
    target_username = body_params.get('username')

    cookies = request.cookies
    session_id = cookies.split("=",1)[1]
    
    # Lấy thông tin của Peer A (người khởi tạo)
    with STATE_LOCK:
        session_data = SESSION_STORE.get(session_id)
        if not session_data or session_data.get('status') != 'online':
            response.status_code = 403
            response.setbody(b'{"message": "Peer A is not fully online/registered"}')
            response.headers['Content-Type'] = 'application/json'
            return
            
        source_username = session_data.get('username')
        ip = session_data.get('ip')
        p2p_port = session_data.get('p2p_port')

    if source_username == target_username:
        response.status_code = 400
        response.headers['Content-Type'] = 'application/json'
        message = build_error_response_json_bytes(400, "Cannot connect to your self")
        response.setbody(message)
        return
        
    # --- BƯỚC 1: Xử lý trạng thái kết nối (CHANNEL_STORE) ---
    target_sessionid = lookup(target_username)
    
    if not target_sessionid:
        response.status_code = 404
        response.headers['Content-Type'] = 'application/json'
        message = build_error_response_json_bytes(404, f"Target user {target_username} not found or offline.")
        response.setbody(message)
        return
        
    connection_already_exists = False
    
    with STATE_LOCK:
        channel_A = CHANNEL_STORE.get(session_id, [])
        if target_sessionid in channel_A:
             connection_already_exists = True

        if not connection_already_exists:
            # Nếu kết nối chưa tồn tại, thêm vào CHANNEL_STORE (hai chiều)
            channel_A.append(target_sessionid)
            CHANNEL_STORE[session_id] = channel_A

            target_channel_B = CHANNEL_STORE.get(target_sessionid, [])
            if session_id not in target_channel_B:
                 target_channel_B.append(session_id)
                 CHANNEL_STORE[target_sessionid] = target_channel_B
        
    # --- BƯỚC 2: GỬI THÔNG BÁO TỚI PEER ĐÍCH (SIGNALING INITIATION) ---
    if target_sessionid:
        with STATE_LOCK:
            target_session_data = SESSION_STORE.get(target_sessionid)
            target_ip = target_session_data.get('ip')
            target_port = target_session_data.get('p2p_port')
        
        if target_ip and target_port:
            print(f"[Tracker] Gửi yêu cầu khởi tạo kết nối P2P tới Peer B ({target_username})...")
            
            # Thông báo cho Peer B rằng Peer A (source_username) muốn kết nối
            notification_body = {
                "initiator_username": source_username, # Ai là người khởi tạo
                "initiator_ip": ip,
                "initiator_port": p2p_port
            }
            
            # Gửi POST tới Peer B 
            success = send_peer_notification(target_ip, target_port, target_username, notification_body)
            
            if not success:
                response.status_code = 500
                response.headers['Content-Type'] = 'application/json'
                message = build_error_response_json_bytes(500, "Failed to notify target peer B")
                response.setbody(message)
                return
        
    # --- BƯỚC 3: Phản hồi về cho Peer A (người khởi tạo) ---
    if connection_already_exists:
        response.status_code = 409
        response.headers['Content-Type'] = 'application/json'
        message = build_error_response_json_bytes(409, "Already in connection")
        response.setbody(message)
    else:  
        response.reason = "OK"
        response.status_code = 200
        response.headers['Content-Type'] = 'application/json'
        # Peer A (người khởi tạo) sẽ nhận thông báo thành công và bắt đầu tạo SDP Offer
        response.setbody(build_error_response_json_bytes(200, "Connection initiated. Start creating SDP Offer."))

    return
            
@app.route('/connect-peer', methods=['GET'])
def connect_peer_get_route(request, response, adapter):
    """
    Dummy route.
    """
    if check_authentication(request, response, adapter) is None:
        return 
    response.status_code = 200

    response.headers['Content-Type'] = 'application/json'

# =========================================================
# 💬 ROUTE HANDLERS: DUMMY P2P ACKNOWLEDGEMENT
# (Giao tiếp P2P thực sự diễn ra qua Socket trực tiếp)
# =========================================================

@app.route('/broadcast-peer', methods=['POST'])
def broadcast_peer_route(request, response, adapter):
    
    if check_authentication(request, response, adapter) is None:
        return
    
    response.status_code = 200
    response.setbody(b'{"status": "P2P Broadcast Acknowledged by Control Plane"}')
    response.headers['Content-Type'] = 'application/json'


@app.route('/send-peer', methods=['GET'])
def send_peer_get_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
    response.status_code = 200
    response.headers['Content-Type'] = 'application/json'

@app.route('/send-peer', methods=['POST'])
def send_peer_route(request, response, adapter):
    """Dummy Route: Thông báo Server rằng Client đang gửi tin nhắn trực tiếp (P2P)."""
    if check_authentication(request, response, adapter) is None:
        return
    response.status_code = 200
    response.setbody(b'{"status": "P2P Send Acknowledged by Control Plane"}')
    response.headers['Content-Type'] = 'application/json'
    
# =========================================================
# 📢 WEBRTC SIGNALING ROUTES (P2P Bắt tay)
# =========================================================

# --- 1. LƯU OFFER (Từ Peer Khởi tạo) ---
@app.route('/webrtc/offer', methods=['POST'])
def save_offer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
    
    payload = parse_body_params(request.body, 'json')
    # payload['username'] là Peer đích, payload['payload'] là Offer SDP
    target_user = payload.get('username')
    offer_data = payload.get('payload')
    
    if not target_user or not offer_data:
        response.status_code = 400
        response.setbody(build_error_response_json_bytes(400, "Missing username or payload (Offer)"))
        response.headers['Content-Type'] = 'application/json'
        return
    
    with WEBRTC_SIGNAL_LOCK:
        # Khởi tạo kho lưu trữ cho Peer đích nếu chưa có
        if target_user not in WEBRTC_SIGNAL_STORE:
            WEBRTC_SIGNAL_STORE[target_user] = {'offer': None, 'answer': None, 'ice_candidates': []}
        
        # Lưu Offer mới nhất
        WEBRTC_SIGNAL_STORE[target_user]['offer'] = offer_data
        
    print(f"[WebRTC] Đã lưu Offer cho Peer: {target_user}")
    response.status_code = 200
    response.setbody(b'{"status": "Offer saved"}')
    response.headers['Content-Type'] = 'application/json'

# --- 2. LẤY OFFER (Từ Peer Nhận) ---
@app.route('/webrtc/offer', methods=['GET'])
def get_offer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
    
    # Lấy username của Peer đang cần tìm Offer (targetUsername trong Client)
    target_user = request.params.get("username")
    
    if not target_user:
        response.status_code = 400
        set_json_response(response, {"message": "Missing username parameter"}, 400)
        return
        
    offer = None
    with WEBRTC_SIGNAL_LOCK:
        if target_user in WEBRTC_SIGNAL_STORE and WEBRTC_SIGNAL_STORE[target_user]['offer']:
            offer = WEBRTC_SIGNAL_STORE[target_user]['offer']
            # Xóa Offer sau khi lấy để Peer B không lấy lại
            WEBRTC_SIGNAL_STORE[target_user]['offer'] = None 
    
    if offer:
        print(f"[WebRTC] Trả về Offer cho Peer: {target_user}")
        response.status_code = 200
        response.setbody(json.dumps({"sdp": offer}).encode('utf-8')) # Trả về SDP
        response.headers['Content-Type'] = 'application/json'
    else:
        # 404 là phản hồi mong đợi khi chưa có tín hiệu
        response.status_code = 404
        response.setbody(b'{}') 
        response.headers['Content-Type'] = 'application/json'

# --- 3. LƯU ANSWER (Từ Peer Nhận) ---
@app.route('/webrtc/answer', methods=['POST'])
def save_answer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
        
    payload = parse_body_params(request.body, 'json')
    target_user = payload.get('username')
    answer_data = payload.get('payload')
    
    if not target_user or not answer_data:
        response.status_code = 400
        response.setbody(build_error_response_json_bytes(400, "Missing username or payload (Answer)"))
        response.headers['Content-Type'] = 'application/json'
        return
    
    with WEBRTC_SIGNAL_LOCK:
        if target_user not in WEBRTC_SIGNAL_STORE:
            WEBRTC_SIGNAL_STORE[target_user] = {'offer': None, 'answer': None, 'ice_candidates': []}
        
        WEBRTC_SIGNAL_STORE[target_user]['answer'] = answer_data
        
    print(f"[WebRTC] Đã lưu Answer cho Peer: {target_user}")
    response.status_code = 200
    response.setbody(b'{"status": "Answer saved"}')
    response.headers['Content-Type'] = 'application/json'

# --- 4. LẤY ANSWER (Từ Peer Khởi tạo) ---
@app.route('/webrtc/answer', methods=['GET'])
def get_answer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
        
    target_user = request.params.get("username")
    if not target_user:
        response.status_code = 400
        set_json_response(response, {"message": "Missing username parameter"}, 400)
        return
        
    answer = None
    with WEBRTC_SIGNAL_LOCK:
        if target_user in WEBRTC_SIGNAL_STORE and WEBRTC_SIGNAL_STORE[target_user]['answer']:
            answer = WEBRTC_SIGNAL_STORE[target_user]['answer']
            WEBRTC_SIGNAL_STORE[target_user]['answer'] = None # Xóa sau khi lấy
    
    if answer:
        print(f"[WebRTC] Trả về Answer cho Peer: {target_user}")
        response.status_code = 200
        response.setbody(json.dumps({"sdp": answer}).encode('utf-8'))
        response.headers['Content-Type'] = 'application/json'
    else:
        response.status_code = 404
        response.setbody(b'{}')
        response.headers['Content-Type'] = 'application/json'

# --- 5. LƯU ICE CANDIDATES (Từ cả hai Peer) ---
@app.route('/webrtc/ice', methods=['POST'])
def add_ice_candidate_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
        
    payload = parse_body_params(request.body, 'json')
    target_user = payload.get('username')
    candidate_data = payload.get('payload')
    
    if not target_user or not candidate_data:
        response.status_code = 400
        response.setbody(build_error_response_json_bytes(400, "Missing username or payload (ICE)"))
        response.headers['Content-Type'] = 'application/json'
        return
    
    with WEBRTC_SIGNAL_LOCK:
        if target_user not in WEBRTC_SIGNAL_STORE:
            WEBRTC_SIGNAL_STORE[target_user] = {'offer': None, 'answer': None, 'ice_candidates': []}
            
        # Thêm ICE Candidate vào danh sách chờ
        WEBRTC_SIGNAL_STORE[target_user]['ice_candidates'].append(candidate_data)
        
    response.status_code = 200
    response.setbody(b'{"status": "ICE candidate saved"}')
    response.headers['Content-Type'] = 'application/json'

# --- 6. LẤY ICE CANDIDATES (Từ Peer đối diện) ---
@app.route('/webrtc/ice', methods=['GET'])
def get_ice_candidates_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return
        
    target_user = request.params.get("username")
    if not target_user:
        response.status_code = 400
        set_json_response(response, {"message": "Missing username parameter"}, 400)
        return
        
    candidates = []
    with WEBRTC_SIGNAL_LOCK:
        if target_user in WEBRTC_SIGNAL_STORE:
            # Lấy tất cả và xóa chúng khỏi danh sách (để tránh lấy lại)
            candidates = WEBRTC_SIGNAL_STORE[target_user]['ice_candidates']
            WEBRTC_SIGNAL_STORE[target_user]['ice_candidates'] = []
    
    response.status_code = 200
    # Trả về một mảng để client dễ dàng xử lý
    response.setbody(json.dumps({"ice_candidates": candidates}).encode('utf-8'))
    response.headers['Content-Type'] = 'application/json'

"""dummy route"""
@app.route('/hello', methods=['PUT'])
def hello(request, response, adapter):
    # Dummy route: Need to accept request, response, adapter arguments
    response.status_code = 200
    response.setbody(b'{"message": "Hello from PUT"}')
    response.headers['Content-Type'] = 'application/json'

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='SampleApp', description='WeApRous sample app')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
    args = parser.parse_args()
    app.prepare_address(args.server_ip, args.server_port)
    app.run()