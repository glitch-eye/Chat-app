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
import socket
import threading # Cần thiết cho cơ chế Lock
import argparse
import uuid # Cần thiết để tạo ID duy nhất

from daemon.weaprous import WeApRous
from daemon.httpadapter import HttpAdapter, parse_body_params

# 🟢 Khóa (Lock) để đảm bảo an toàn khi cập nhật trạng thái chung
STATE_LOCK = threading.Lock()
PORT = 8000  # Default port

CHANNEL_STORE = {
    'global_chat': set() 
}

app = WeApRous()


SESSION_STORE = {}
"""
Key: session_id (UUID)\n
Value: {'username': str, 'ip': str, 'p2p_port': int, 'status': str, 'channels': list}\n
"""

# Trong start_sampleapp.py (Sau các định nghĩa STORE)

def check_authentication(request, response, adapter):
    """Kiểm tra session_id trong Cookie và trả về username."""
    session_id = request.cookies.get('session_id')

    if session_id is None:
        # THẤT BẠI: Phục vụ Login 401
        response.status_code = 401
        response.body = adapter.UNAUTHORIZED_PAGE
    
    with STATE_LOCK:
        user_session = SESSION_STORE.get(session_id)

    if not user_session:
        response.status_code = 401
        response.body = adapter.UNAUTHORIZED_PAGE
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return None
    
    return user_session['username']

@app.route('/', methods=['GET'])
def home_route(request, response, adapter):
    """
    TASK 1B (Mới): Xử lý GET / (Đọc và Kiểm tra Session ID)
    """
    if check_authentication(request, response, adapter) is not None:
        response.status_code = 200
        response.body = adapter.INDEX_PAGE

    
    response.headers['Content-Type'] = 'text/html; charset=utf-8'


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
        
        # 2. 🟢 LƯU THÔNG TIN SESSION VÀO STORE
        SESSION_STORE[session_id] = {'username': username}
        
        # 3. 🟢 GÁN HEADER SET-COOKIE VÀ GỬI ID VỀ CLIENT
        # HttpOnly ngăn chặn XSS đọc cookie, Max-Age là 1 giờ (3600 giây)
        session_cookie = f"session_id={session_id}; Max-Age=3600; Path=/; HttpOnly" 
        # response.headers['Set-Cookie'] = session_cookie
        request.prepare_cookies(session_cookie)
        response.status_code = 200
        response.body = adapter.INDEX_PAGE
        print(f"[AUTH] User {username} logged in. Session ID: {session_id}")
    else:
        # Thất bại: 401 Unauthorized
        response.status_code = 401
        response.body = adapter.UNAUTHORIZED_PAGE
    
    response.headers['Content-Type'] = 'text/html; charset=utf-8'


@app.route('/hello', methods=['PUT'])
def hello(request, response, adapter): # 🔴 Sửa lại chữ ký hàm
    """Handle greeting via PUT request."""
    # Logic kiểm tra Session ID nếu đây là API cần Auth
    session_id = request.cookies.get('session_id')
    if session_id in SESSION_STORE:
        print (f"[SampleApp] ['PUT'] Hello by user {SESSION_STORE[session_id]['username']} to {request.url}")
        response.status_code = 200
        response.body = b"Hello Handled by Route!"
    else:
        response.status_code = 401
        response.body = adapter.UNAUTHORIZED_PAGE
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

# @app.route('/hello', methods=['PUT'])
# def hello(headers, body):
#     """
#     Handle greeting via PUT request.

#     This route prints a greeting message to the console using the provided headers
#     and body.

#     :param headers (str): The request headers or user identifier.
#     :param body (str): The request body or message payload.
#     """
#     print ("[SampleApp] ['PUT'] Hello in {} to {}".format(headers, body))

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