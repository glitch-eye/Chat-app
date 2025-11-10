import socket
import argparse
import time
from urllib.parse import urlencode, parse_qs
import re
import json

# =======================================================
# CẤU HÌNH
# =======================================================
DEFAULT_PROXY_IP = '127.0.0.1' 
DEFAULT_PROXY_PORT = 8080      
TARGET_HOST_APP1 = "app1.local" 

# --- HÀM GIAO TIẾP VỚI PROXY (Sử dụng socket) ---

def send_http_request(host, port, method, path, headers=None, body=None, proxy_host=TARGET_HOST_APP1):
    """Gửi Request HTTP tới Proxy và nhận toàn bộ Response."""
    
    request_headers = {
        "Host": proxy_host,
        "User-Agent": "ClientRunner/1.0",
        "Connection": "close"
    }
    if headers:
        request_headers.update(headers)

    body_bytes = b""
    if body:
        if isinstance(body, dict): body_bytes = urlencode(body).encode('utf-8')
        else: body_bytes = body.encode('utf-8')
        request_headers["Content-Length"] = str(len(body_bytes))
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    
    request_line = f"{method} {path} HTTP/1.1\r\n"
    header_lines = [f"{k}: {v}" for k, v in request_headers.items()]
    request_data = request_line + "\r\n".join(header_lines) + "\r\n\r\n"
    request_data_bytes = request_data.encode('utf-8') + body_bytes
    print(request_data_bytes)
    
    response_data = b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(request_data_bytes)
            
            # Đọc Response
            s.settimeout(2.0) 
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response_data += chunk
            
            return parse_response(response_data)
            
    except Exception as e:
        print(f"[ERROR] Lỗi kết nối đến Proxy {host}:{port}: {e}")
        return None, None, None, None

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
                # Lưu header ở dạng lowercase để dễ truy cập
                headers[key.lower()] = value.strip() 
                
        return status_code, header_text, headers, body_bytes

    except Exception as e:
        print(f"[ERROR] Lỗi phân tích Response: {e}")
        return 'N/A', b'', {}, b''

# --- HÀM MÔ PHỎNG BROWSER ---

def extract_login_info(html_body_bytes):
    """Trích xuất Form Action và các trường Input từ Body HTML."""
    
    html_text = html_body_bytes.decode('utf-8', errors='ignore')
    
    # Regex tìm kiếm thẻ <form> POST trỏ tới /login
    form_match = re.search(r'<form\s+method="(?P<method>POST)"\s+action="(?P<action>/login|/login/?)".*?>(?P<content>.*?)</form>', html_text, re.DOTALL | re.IGNORECASE)

    if form_match:
        form_action = form_match.group('action')
        form_content = form_match.group('content')
        
        # Trích xuất Input Fields
        input_fields = re.findall(r'<input.*?name="(?P<name>.*?)".*?>', form_content, re.IGNORECASE)
        
        simulated_data = {}
        if 'username' in input_fields and 'password' in input_fields:
            # Mô phỏng quá trình tương tác (Tự động điền)
            simulated_data = {"username": "admin", "password": "password"}
            return form_action, simulated_data
            
    return None, None

def extract_login_link(html_body_bytes):
    """Trích xuất link 'login.html' từ Body HTML 401."""
    html_text = html_body_bytes.decode('utf-8', errors='ignore')
    
    # Regex tìm kiếm thẻ <a href="login.html">
    link_match = re.search(r'<a\s+href=["\'](?P<href>login|/login)["\']', html_text, re.IGNORECASE)
    
    if link_match:
        return link_match.group('href')
        
    return None

def run_scenario(proxy_ip, proxy_port):
    print("\n\n==================================================")
    print(" 🧪 BẮT ĐẦU KỊCH BẢN MÔ PHỎNG BROWSER (TASK 1A/1B) ")
    print("==================================================")
    
    # --- BƯỚC 1: REQUEST LẦN 1 - GET / (Kiểm tra 401) ---
    print(f"\n[BƯỚC 1] Gửi GET / (Không Cookie) tới {TARGET_HOST_APP1}...")
    status, _, headers, body_bytes = send_http_request(proxy_ip, proxy_port, 'GET', '/', proxy_host=TARGET_HOST_APP1)
    
    if status != '401':
        print(f"  ❌ LỖI: Kỳ vọng 401 Unauthorized, nhận được {status}. Dừng kịch bản.")
        return
    print(f"  ✅ Nhận Response {status} (Unauthorized). Tiếp tục.")
    
    login_link = extract_login_link(body_bytes)
    if not login_link:
        print("  ❌ LỖI: Không tìm thấy link 'login.html' trong body 401. Dừng kịch bản.")
        return
        
    # --- BƯỚC 2: REQUEST LẦN 2 - GET /login.html (Click link) ---
    print(f"\n[BƯỚC 2] Mô phỏng Click link. Gửi GET {login_link} để lấy Form...")
    status_get_login, _, _, body_bytes_login = send_http_request(proxy_ip, proxy_port, 'GET', login_link, proxy_host=TARGET_HOST_APP1)
    
    if status_get_login != '200':
        print(f"  ❌ LỖI: Kỳ vọng 200 OK cho /login.html, nhận được {status_get_login}. Dừng kịch bản.")
        return
    print(f"  ✅ Nhận Response {status_get_login} (OK). Trích xuất Form.")
    
    # Trích xuất thông tin Form từ body_bytes_login
    form_action, login_payload = extract_login_info(body_bytes_login)
    
    if not login_payload:
        print("  ❌ Dừng kịch bản: Không thể trích xuất Form Login hợp lệ.")
        return
        
    print(f"  -> Form Action: POST {form_action}")
    print(f"  -> Dữ liệu mô phỏng: {login_payload}")

    # --- BƯỚC 3: REQUEST LẦN 3 - POST /login (Xác thực và lấy Cookie) ---
    print(f"\n[BƯỚC 3] Gửi POST {form_action} với dữ liệu đã mô phỏng...")
    status_post, _, headers_post, _ = send_http_request(
        proxy_ip, proxy_port, 
        'POST', form_action, 
        body=login_payload,
        proxy_host=TARGET_HOST_APP1
    )
    
    set_cookie_header = headers_post.get('set-cookie', '')
    
    print(f"  -> Trạng thái POST: {status_post}")
    if set_cookie_header:
        print("  ✅ Xác thực thành công.")
        print(f"  -> Header Set-Cookie: {set_cookie_header}")
    else:
        print(f"  ❌ LỖI: POST thất bại (Status: {status_post} hoặc thiếu Cookie). Dừng kịch bản.")
        return
        
    print("\n[BƯỚC 4] TEST 1: POST /submit-info/ (Thành công - Gửi IP và Port hợp lệ)")
    
    AUTH_HEADERS = {"cookies": set_cookie_header}
    valid_peer_data = {
        "ip": "192.168.1.50",
        "port": "5000" # Phải gửi dưới dạng string trong body
    }
    
    status_ok, header_ok, headers_ok, body_ok = send_http_request(
        proxy_ip, proxy_port, 
        'POST', '/submit-info/', 
        headers=AUTH_HEADERS,
        body=valid_peer_data,
        proxy_host=TARGET_HOST_APP1
    )
    
    print(f"  -> Trạng thái Response: {status_ok}")
    if status_ok == '200':
        print(f"  ✅ THÀNH CÔNG: API trả về 200 OK.")
    else:
        print(f"  ❌ THẤT BẠI: Kỳ vọng 200 OK, nhận được {status_ok}.")
        
    # -------------------------------------------------------------------
    # --- BƯỚC 5: API TEST 2 - THIẾU DỮ LIỆU (STATUS 400 - Missing IP/Port) ---
    # -------------------------------------------------------------------
    
    print("\n[BƯỚC 5] TEST 2: POST /submit-info/ (Lỗi 400 - Thiếu Port)")
    
    missing_data = {
        "ip": "192.168.1.50"
        # Thiếu "port"
    }
    
    status_missing, header_missing, headers_missing, body_missing = send_http_request(
        proxy_ip, proxy_port, 
        'POST', '/submit-info/', 
        headers=AUTH_HEADERS,
        body=missing_data,
        proxy_host=TARGET_HOST_APP1
    )
    
    print(f"  -> Trạng thái Response: {status_missing}")
    if status_missing == '400':
        print(f"  ✅ THÀNH CÔNG: API trả về 400 BAD REQUEST.")
        # Kiểm tra nội dung lỗi (body_missing là byte chuỗi JSON)
        print(f"  -> Lỗi Server trả về (Reason): {headers_missing.get('content-type', '')} (Body Preview: {body_missing[:50]})") 
    else:
        print(f"  ❌ THẤT BẠI: Kỳ vọng 400 BAD REQUEST, nhận được {status_missing}.")

    # -------------------------------------------------------------------
    # --- BƯỚC 6: API TEST 3 - SAI ĐỊNH DẠNG PORT (STATUS 400 - ValueError) ---
    # -------------------------------------------------------------------
    
    print("\n[BƯỚC 6] TEST 3: POST /submit-info/ (Lỗi 400 - Port không phải số)")
    
    invalid_data = {
        "ip": "192.168.1.50",
        "port": "abc" # Sai định dạng
    }
    
    status_invalid, header_invalid, headers_invalid, body_invalid = send_http_request(
        proxy_ip, proxy_port, 
        'POST', '/submit-info/', 
        headers=AUTH_HEADERS,
        body=invalid_data,
        proxy_host=TARGET_HOST_APP1
    )
    
    print(f"  -> Trạng thái Response: {status_invalid}")
    if status_invalid == '400':
        print(f"  ✅ THÀNH CÔNG: API trả về 400 BAD REQUEST (Lỗi ValueError).")
        # Kiểm tra nội dung lỗi
        print(f"  -> Lỗi Server trả về (Reason): {headers_invalid.get('content-type', '')} (Body Preview: {body_invalid[:50]})") 
    else:
        print(f"  ❌ THẤT BẠI: Kỳ vọng 400 BAD REQUEST, nhận được {status_invalid}.")


    print("\n==================================================")
    print("[HOÀN TẤT KỊCH BẢN KIỂM TRA TỰ ĐỘNG API P2P]")
    print("==================================================")

# =======================================================
# III. HÀM MAIN
# =======================================================

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog='run_client_scenario', 
        description='Mô phỏng Browser để kiểm tra Assignment 1 (HTTP Server và Session Cookie).',
    )
    parser.add_argument('--proxy-ip', default=DEFAULT_PROXY_IP, help='Địa chỉ IP của Proxy Server.')
    parser.add_argument('--proxy-port', type=int, default=DEFAULT_PROXY_PORT, help='Cổng của Proxy Server.')
    
    args = parser.parse_args()
    
    run_scenario(args.proxy_ip, args.proxy_port)