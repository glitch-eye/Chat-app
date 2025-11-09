# run_client_scenario.py
import socket
import argparse
import webbrowser 
import threading
import time
from urllib.parse import urlencode

# =======================================================
# CẤU HÌNH
# =======================================================
DEFAULT_PROXY_IP = '127.0.0.1' 
DEFAULT_PROXY_PORT = 8080      
TARGET_HOST_APP1 = "app2.local" 
TARGET_HOST_APP2 = "app2.local"

DEFAULT_BACKEND_IP = '0.0.0.0'
DEFAULT_BACKEND_PORT = 8000 

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
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(request_data_bytes)
            
            response_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response_data += chunk
            
            response_text = response_data.decode('utf-8', errors='ignore')
            status_line = response_text.split('\r\n')[0]
            status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else 'N/A'
            
            return status_code, None, response_text
    except Exception as e:
        print(f"[ERROR] Lỗi kết nối đến Proxy: {e}")
        return None, None, None


# =======================================================
# KỊCH BẢN CHÍNH (CLIENT)
# =======================================================

def run_scenario(proxy_ip, proxy_port):
    print("\n\n==================================================")
    print(" 🧪 BẮT ĐẦU KỊCH BẢN CLIENT (SERVER-SIDE MODIFIED) ")
    print("==================================================")
    
    # 1. GỬI REQUEST và nhận Response 401
    print("[BƯỚC 1] Gửi GET / (app1.local) và nhận Response 401...")
    status, _, response_text = send_http_request(proxy_ip, proxy_port, 'GET', '/', proxy_host=TARGET_HOST_APP1)
    
    # 🔑 KIỂM TRA: Liên kết phải là URL tuyệt đối
    expected_link = f'href="http://{TARGET_HOST_APP2}:{proxy_port}/login.html"'
    ui_url = f""
    print(status)
    if int(status) == 404:
        ui_url = f"http://{DEFAULT_BACKEND_IP}:{DEFAULT_BACKEND_PORT}/unauthorize.html"
        webbrowser.open_new_tab(ui_url) 
    elif int(status) == 200:
        ui_url = f"http://{DEFAULT_BACKEND_IP}:{DEFAULT_BACKEND_PORT}/index.html"
        webbrowser.open_new_tab(ui_url) 
    print(f"\n[BƯỚC 2] MỞ GIAO DIỆN UI")
    print(f"  🟢 Mở trình duyệt tại địa chỉ: {ui_url}")
    
    
    
    print("\n[HOÀN TẤT KIỂM TRA TỰ ĐỘNG]")
    print("--------------------------------------------------")

# =======================================================
# III. HÀM MAIN
# =======================================================

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog='run_client_scenario', 
        description='Chạy kịch bản kiểm thử client (chỉ kiểm tra Server-side modification).',
    )
    parser.add_argument('--proxy-ip', default=DEFAULT_PROXY_IP, help='Địa chỉ IP của Proxy Server.')
    parser.add_argument('--proxy-port', type=int, default=DEFAULT_PROXY_PORT, help='Cổng của Proxy Server.')
    
    args = parser.parse_args()
    
    run_scenario(args.proxy_ip, args.proxy_port)