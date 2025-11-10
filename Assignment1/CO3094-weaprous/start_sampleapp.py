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
import subprocess
import sys

PEER_CLIENT_PROCESSES = {} 
PEER_CLIENT_LOCK = threading.Lock()
# 🟢 Khóa (Lock) để đảm bảo an toàn khi cập nhật trạng thái chung

PORT = 8000  # Default port

app = WeApRous()

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



def get_session_id_from_request():
    """Trích xuất Session ID từ Header Cookie."""
    # Bạn cần đảm bảo logic phân tích Header Cookie trong lớp Request hoạt động
    # Tên cookie: 'sessionid'
    
    # Giả định: self.request.cookies là một dict/CaseInsensitiveDict chứa cookies đã được phân tích.
    with STATE_LOCK:
        cookies = [x for x in SESSION_STORE.keys()]
        return cookies


def handle_get_peer_list(exception_id = None):
    
    # 1. KIỂM TRA XÁC THỰC: Lấy danh sách session_id từ request
    session_id_lst = get_session_id_from_request()
    
    # Kiểm tra tính hợp lệ của danh sách session_id
    if not session_id_lst or not isinstance(session_id_lst, list):
        return []  # Không có session hợp lệ → trả về danh sách rỗng
    
    clean_peer_list = []

    channel = []
    if exception_id is not None:
        with STATE_LOCK:
            channel = CHANNEL_STORE.get(exception_id, [])
    # 2. ĐỌNG BỘ TRUY CẬP SESSION_STORE VỚI LOCK
    with STATE_LOCK:
        for session_id in session_id_lst:
            # Kiểm tra xem session_id có tồn tại trong SESSION_STORE không
            if session_id == exception_id:
                continue  # Bỏ qua session không hợp lệ
            
            session_data = SESSION_STORE[session_id]
            
            # Trích xuất các trường cần thiết
            username = session_data.get('username')
            ip = session_data.get('ip')
            p2p_port = session_data.get('p2p_port')
            status = session_data.get('status')
            
            # Chỉ thêm vào danh sách nếu các trường bắt buộc tồn tại và hợp lệ
            if exception_id is not None:
                clean_peer_list.append((username, ip, p2p_port, status, session_id in channel))
            else:
                clean_peer_list.append((username, ip, p2p_port, status))
    
    return clean_peer_list

def build_error_response_json_bytes(status_code, message):
    """Tạo body JSON bytes cho phản hồi lỗi."""
    json_string = json.dumps({"message": message})
    return json_string.encode('utf-8')

def lookup(username):
    """Tìm sectionid cho username"""
    session_id_lst = get_session_id_from_request()
    
    # Kiểm tra tính hợp lệ của danh sách session_id
    if not session_id_lst or not isinstance(session_id_lst, list):
        return None  # Không có session hợp lệ → trả về danh sách rỗng
    
    # 2. ĐỌNG BỘ TRUY CẬP SESSION_STORE VỚI LOCK
    with STATE_LOCK:
        for session_id in session_id_lst:
            # Kiểm tra xem session_id có tồn tại trong SESSION_STORE không
            
            session_data = SESSION_STORE[session_id]
            # Trích xuất các trường cần thiết
            if username == session_data.get('username'):
                return session_id
    return None
# -------------------------------------------------------
# LOGIC TẢI VÀ SỬA ĐỔI (CHỈ CHẠY MỘT LẦN KHI STARTUP)
# -------------------------------------------------------

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

@app.route('/submit-info', methods=['GET'])
def submit_info_route(request, response, adapter):
    """
    Peer Registration: Cập nhật IP và P2P Port của Peer vào Tracker.
    """
    response.status_code = 200
    response.reason = "OK"
    request.headers["authorization"] = True
    
@app.route('/submit-info', methods=['POST'])
def submit_info_route(request, response, adapter):
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
        response.reason = b'{"Username have been taken"}'
        response.headers['Content-Type'] = 'application/json'
        return
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
    cookies = request.cookies
    session_id = cookies.split('=',1)[1]
    if check_authentication(request, response, adapter) is None:
        return
    with STATE_LOCK:
        if SESSION_STORE[session_id]["status"] == "online":
            if session_id not in CHANNEL_STORE["global_chat"]:
                CHANNEL_STORE["global_chat"] += [session_id]
        else: 
            SESSION_STORE[session_id]["status"] = "online"
            if session_id not in CHANNEL_STORE["global_chat"]:
                CHANNEL_STORE["global_chat"] += [session_id]
    with STATE_LOCK:
        session_data = SESSION_STORE[session_id]
        username = session_data['username']
        ip = session_data['ip']
        p2p_port = session_data['p2p_port']
    start_process('start_sampleapp.py', ip, p2p_port, f"peer_client {username}", session_id)
    

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
    cookies = request.cookies
    session_id = cookies.split('=',1)[1]
    peer_tuples = handle_get_peer_list(session_id)
    peer_data_list = []
    for peer in peer_tuples:
        peer_data_list.append({
            "username": peer[0], "ip": peer[1], "p2p_port": peer[2], "status": peer[3], "isConnected": peer[4]
        })
    
    json_string = json.dumps(peer_data_list)
    response_body_bytes = json_string.encode('utf-8')
    response.headers['Content-Type'] = 'application/json'
    response.setbody(response_body_bytes)
    print(peer_tuples)

@app.route('/connect-peer', methods=['POST'])
def connect_peer_route(request, response, adapter):
    if check_authentication(request, response, adapter) is None:
        return 
    body_params = parse_body_params(request.body,'json')
    t_ip = body_params.get('ip')
    t_p2p_port = body_params.get('port')
    target_username = body_params.get('username')
    print(target_username)

    
    cookies = request.cookies
    session_id = cookies.split("=",1)[1]
    with STATE_LOCK:
        session_data = SESSION_STORE[session_id]
        source_username = session_data.get('username')
        ip = session_data.get('ip')
        p2p_port = session_data.get('p2p_port')
    if source_username == target_username:
        response.status_code = 400
        response.headers['Content-Type'] = 'application/json'
        message = build_error_response_json_bytes(400, "Cannot connect to your self")
        response.setbody(message)
    else:
        target_sessionid = lookup(target_username)
        with STATE_LOCK:
            channel = CHANNEL_STORE.get(session_id)
            if channel is None:
                CHANNEL_STORE[session_id] = [target_sessionid]
            elif target_sessionid in channel:
                response.status_code = 409
                response.headers['Content-Type'] = 'application/json'
                message = build_error_response_json_bytes(409, "Already in connection")
                response.setbody(message)
            else:  
                CHANNEL_STORE[session_id] += [target_sessionid]
                response.reason = "OK"
                response.status_code = 200
                response.headers['Content-Type'] = 'application/json'
                response.setbody(build_error_response_json_bytes(200, "Ongoing"))
    return
            
@app.route('/connect-peer', methods=['GET'])
def connect_peer_route(request, response, adapter):
    """
    Lấy thông tin P2P của một Peer cụ thể bằng Session ID.
    
    Yêu cầu query param: ?session_id=<target_session_id>
    """
    if check_authentication(request, response, adapter) is None:
        return
    

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

@app.route('/send-peer', methods=['GET'])
def send_peer_route(request, response, adapter):
    """kiểm tra và push chat ui lên"""
    if check_authentication(request, response, adapter) is None:
        return
    

@app.route('/send-peer', methods=['POST'])
def send_peer_route(request, response, adapter):
    """Dummy Route: Thông báo Server rằng Client đang gửi tin nhắn trực tiếp (P2P)."""
    if check_authentication(request, response, adapter) is None:
        return
    
    response.status_code = 200
    response.body = b'{"status": "P2P Direct Send Acknowledged by Control Plane"}'
    response.headers['Content-Type'] = 'application/json'



"""dummy route"""
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