import socket
import argparse

# Cấu hình Client mặc định
PROXY_IP = '0.0.0.0' 
PROXY_PORT = 8080     
TARGET_HOST = "app2.local" # Host ảo cần test định tuyến

def test_proxy_connection(proxy_ip, proxy_port):
    """
    Gửi Request GET đơn giản tới Proxy và in Response.
    
    Sử dụng header Host: app1.local để yêu cầu Proxy định tuyến.
    """
    
    # Request HTTP thô
    request_data = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        f"User-Agent: ProxyTester/1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    print(f"===================================================")
    print(f"  [CLIENT] Gửi Request tới Proxy: {proxy_ip}:{proxy_port}")
    print(f"  [HEADER] Host: {TARGET_HOST}")
    print(f"===================================================")

    try:
        # 1. Tạo và kết nối socket tới Proxy
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((proxy_ip, proxy_port))
            
            # 2. Gửi Request
            s.sendall(request_data.encode('utf-8'))
            
            # 3. Nhận Response
            response_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            # 4. In kết quả
            print("\n[RESPONSE] Nhận được từ Proxy:")
            print(response_data.decode('utf-8', errors='ignore'))

    except ConnectionRefusedError:
        print(f"\n[ERROR] 🛑 KHÔNG KẾT NỐI ĐƯỢC! Hãy đảm bảo Proxy đang chạy tại {proxy_ip}:{proxy_port}.")
    except socket.error as e:
        print(f"\n[ERROR] 🛠️ Lỗi Socket: {e}")
    except Exception as e:
        print(f"\n[ERROR] Lỗi không xác định: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ProxyTester', 
        description='Kiểm tra kết nối Proxy và định tuyến Host.',
        epilog=f"Default Proxy is {PROXY_IP}:{PROXY_PORT}"
    )
    parser.add_argument('--server-ip',
        type=str,
        default=PROXY_IP,
        help='Địa chỉ IP của Proxy Server.'
    )
    parser.add_argument(
        '--server-port',
        type=int,
        default=PROXY_PORT,
        help='Cổng của Proxy Server.'
    )
 
    args = parser.parse_args()
    test_proxy_connection(args.server_ip, args.server_port)