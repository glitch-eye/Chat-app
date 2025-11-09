import socket
import argparse
import time
from urllib.parse import urlencode, parse_qs
import re
from io import StringIO # Dùng để đọc Response dễ dàng hơn

# =======================================================
# CẤU HÌNH
# =======================================================
DEFAULT_PROXY_IP = '127.0.0.1' 
DEFAULT_PROXY_PORT = 8080      
TARGET_HOST_APP1 = "app2.local" 

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
                headers[key.lower()] = value.strip()
                
        return status_code, header_text, headers, body_bytes

    except Exception as e:
        print(f"[ERROR] Lỗi phân tích Response: {e}")
        return 'N/A', b'', {}, b''

# --- HÀM MÔ PHỎNG BROWSER ---

def console_render_html(html_body_bytes):
    """Mô phỏng 'render' HTML bằng cách trích xuất Form và in ra Console."""
    
    html_text = html_body_bytes.decode('utf-8', errors='ignore')
    
    print("--- CONSOLE RENDERER (Mô phỏng Giao diện Form) ---")
    
    # 1. Trích xuất Form (Regex đơn giản)
    # Tìm kiếm thẻ <form> và các input fields
    form_match = re.search(r'<form\s+method="(?P<method>POST)"\s+action="(?P<action>/login|/login/?)".*?>(?P<content>.*?)</form>', html_text, re.DOTALL | re.IGNORECASE)

    if form_match:
        form_action = form_match.group('action')
        form_content = form_match.group('content')
        
        print(f"  [Form Action]: POST {form_action}")
        
        # 2. Trích xuất Input Fields (Regex đơn giản)
        input_fields = re.findall(r'<input.*?name="(?P<name>.*?)".*?>', form_content, re.IGNORECASE)
        
        print(f"  [Input Fields]: {input_fields}")
        print("-----------------------------------------------------")
        
        # Mô phỏng quá trình tương tác (Tự động điền)
        simulated_data = {}
        if 'username' in input_fields and 'password' in input_fields:
            simulated_data = {"username": "admin", "password": "password"}
            print(f"  ✅ Mô phỏng người dùng nhập: {simulated_data}")
            print("  ✅ Mô phỏng nhấn nút Submit...")
            return form_action, simulated_data
            
    else:
        print("  ❌ Không tìm thấy Form Login hợp lệ trong Body HTML.")
        print("  [Body Preview]:", html_text[:200].replace('\n', ' '))
        
    return None, None

def run_scenario(proxy_ip, proxy_port):
    print("\n\n==================================================")
    print(" 🧪 BẮT ĐẦU KỊCH BẢN MÔ PHỎNG BROWSER (TASK 1A/1B) ")
    print("==================================================")
    
    # --- BƯỚC 1: REQUEST LẦN 1 - GET / (Kiểm tra 401) ---
    print(f"\n[BƯỚC 1] Gửi GET / (Không Cookie) tới {TARGET_HOST_APP1}...")
    status, _, headers, body_bytes = send_http_request(proxy_ip, proxy_port, 'GET', '/', proxy_host=TARGET_HOST_APP1)
    
    if status != '401':
        print(f"  ❌ LỖI: Kỳ vọng 401 Unauthorized, nhận được {status}. Kiểm tra lại Server.")
        if status == '200':
             print("  (Có thể do Server chưa có logic chuyển hướng/bảo vệ trang /)")
        return
    print(f"  ✅ Nhận Response {status} (Unauthorized). Tiếp tục.")

    # --- BƯỚC 2: "RENDER" VÀ TƯƠNG TÁC (Tạo POST Request) ---
    print("\n[BƯỚC 2] 'Render' Body HTML và Mô phỏng Tương tác UI...")
    
    form_action, login_payload = console_render_html(body_bytes)
    
    if not login_payload:
        print("  ❌ Dừng kịch bản: Không thể mô phỏng tương tác Form.")
        return

    # --- BƯỚC 3: REQUEST LẦN 2 - POST /login (Xác thực và lấy Cookie) ---
    print(f"\n[BƯỚC 3] Gửi POST {form_action} với dữ liệu đã mô phỏng...")
    status_post, header_text_post, headers_post, _ = send_http_request(
        proxy_ip, proxy_port, 
        'POST', form_action, 
        body=login_payload,
        proxy_host=TARGET_HOST_APP1
    )
    
    set_cookie_header = headers_post.get('set-cookie', '')
    
    print(f"  -> Trạng thái POST: {status_post}")
    if status_post == '200' and 'auth=true' in set_cookie_header:
        print("  ✅ Xác thực thành công.")
        print(f"  -> Header Set-Cookie: {set_cookie_header.split(';')[0] + '...'}")
    else:
        print(f"  ❌ LỖI: POST thất bại (Status: {status_post} hoặc thiếu Cookie).")
        return
        
    # --- BƯỚC 4: REQUEST LẦN 3 - GET / (Kiểm tra Cookie) ---
    
    # Trích xuất Cookie string (chỉ lấy auth=true)
    cookie_value = set_cookie_header.split(';')[0]
    
    print(f"\n[BƯỚC 4] Gửi GET / LẠI với Cookie: {cookie_value}...")
    
    headers_with_cookie = {"Cookie": cookie_value}
    status_cookie, _, _, _ = send_http_request(
        proxy_ip, proxy_port, 'GET', '/', 
        headers=headers_with_cookie, 
        proxy_host=TARGET_HOST_APP1
    )
    
    if status_cookie == '200':
        print(f"  ✅ Nhận Response {status_cookie} với Cookie. TASK 1B (Access Control) thành công.")
    else:
        print(f"  ❌ LỖI: Nhận Response {status_cookie} dù đã gửi Cookie hợp lệ.")

    print("\n==================================================")
    print("[HOÀN TẤT KỊCH BẢN KIỂM TRA TỰ ĐỘNG]")
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