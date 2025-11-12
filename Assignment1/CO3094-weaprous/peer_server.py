# SỬA LẠI: Loại bỏ các import không rõ ràng, sử dụng thư viện chuẩn.
import json
import argparse
import socket
import threading
import re # Thêm để parsing HTTP đơn giản
import sys # Import sys cho lỗi

PORT = 8000

# Khóa để đồng bộ truy cập vào dữ liệu
mess_state = threading.Lock()

# BỘ NHỚ LƯU TRỮ DỮ LIỆU
# Tin nhắn thô
message_mark = {
    "unread" : [],
    "read" : []
} 
# Tín hiệu WebRTC: lưu trữ tín hiệu gửi đến Peer này
# { type: [data, data, ...], ... }
signaling_store = {
    "offer": [],
    "answer": [],
    "ice": []
}
signaling_state = threading.Lock()

# Biến cờ cho việc chạy Backend
is_running = threading.Event()

class Receiver:
    
    def __init__(self):
        self.routes = {}
        self.ip = None
        self.port = None
        return

    def prepare_address(self, ip, port):
        self.ip = ip
        self.port = port

    def route(self, path, methods=['GET']):
        def decorator(func):
            for method in methods:
                self.routes[(method.upper(), path)] = func
            return func
        return decorator

    def run_backend(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Thiết lập để tái sử dụng địa chỉ ngay lập tức
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        
        try:
            server.bind((self.ip, self.port)) 
            server.listen(50)
            print(f"[Backend] Listening on {self.ip}:{self.port}")
            if self.routes != {}:
                print(f"[Backend] route settings: {self.routes.keys()}")
            
            is_running.set() 

            while is_running.is_set():
                # Dùng timeout để kiểm tra cờ tắt
                try:
                    server.settimeout(0.5) 
                    conn, addr = server.accept()
                    print(f"[Backend] Accepted connection from {addr}")
                    
                    client_thread = threading.Thread(
                        target=handle_peer,
                        args=(conn, addr, self.routes) 
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except socket.error as e:
                    if is_running.is_set():
                        print(f"Lỗi Socket khi chấp nhận kết nối: {e}")
                    break 
        except socket.error as e:
            print(f"Socket binding error on {self.ip}:{self.port}: {e}")
        except KeyboardInterrupt:
            print("\nServer shutdown requested by user.")
        finally:
            is_running.clear()
            server.close()
            print("[Backend] Server stopped.")

app = Receiver()

# --- CÁC ROUTE WEB RTC SIGNALING MỚI ---
def send_http_response(conn, status_code, status_message, body_data=None, content_type="application/json"):
    """Hàm tiện ích để gửi phản hồi HTTP"""
    if body_data is None:
        body_bytes = b''
    else:
        json_string = json.dumps(body_data)
        body_bytes = json_string.encode('utf-8')

    response = (
        f"HTTP/1.1 {status_code} {status_message}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Access-Control-Allow-Origin: *\r\n" # Cần thiết cho CORS P2P
        f"\r\n"
    ).encode('utf-8') + body_bytes
    
    try:
        conn.sendall(response)
    except socket.error as e:
        print(f"Lỗi gửi phản hồi: {e}")

# 🚨 ĐÃ THÊM: Route BỊ THIẾU mà Tracker Server gọi (send_peer_notification)
@app.route('/webrtc/initiate', methods=['POST'])
def initiate_webrtc_connection(conn, name, signal_data):
    """
    Nhận thông báo KÍCH HOẠT từ Tracker Server.
    Route này cho Peer B biết có Peer A đang muốn kết nối.
    Nó chỉ là một POST request để kích hoạt Peer B.
    """
    print(f"-> Đã nhận thông báo kích hoạt kết nối WebRTC từ Tracker.")
    # Peer B nhận được thông báo này sẽ bắt đầu Polling Tracker (4000) để lấy Offer SDP
    send_http_response(conn, 200, "OK", {"status": "ok", "message": "Initiation notification received"})


@app.route('/webrtc/signal', methods=['POST'])
def receive_webrtc_signal(conn, name, signal_data):
    """
    Route để nhận và lưu tín hiệu SDP Offer, Answer, hoặc ICE Candidates từ Tracker.
    LƯU Ý: Nếu dùng mô hình Polling Tracker, route này có thể không cần thiết 
    vì Tracker tự lưu trữ và Peer Polling Tracker để lấy. 
    Tuy nhiên, giữ lại nếu bạn muốn Peer Server cũng là nơi lưu trữ tín hiệu tạm thời.
    """
    if signal_data and 'type' in signal_data and 'data' in signal_data:
        signal_type = signal_data['type'].lower()
        data = signal_data['data']
        
        if signal_type in signaling_store:
            with signaling_state:
                signaling_store[signal_type].append(data)
            print(f"-> Đã nhận và lưu tín hiệu WebRTC loại: {signal_type}")
            send_http_response(conn, 200, "OK", {"status": "ok", "message": f"Signal {signal_type} received"})
        else:
            send_http_response(conn, 400, "Bad Request", {"error": "Invalid signal type"})
    else:
        send_http_response(conn, 400, "Bad Request", {"error": "Missing 'type' or 'data' in signal body"})

@app.route('/webrtc/poll', methods=['GET'])
def poll_webrtc_signals(conn, name, message):
    """
    Trả về tất cả các tín hiệu WebRTC (Offer/Answer/ICE) đang chờ xử lý.
    Peer Client sẽ dùng hàm này để kiểm tra xem có tín hiệu mới nào được gửi đến nó không.
    """
    all_signals = {}
    total_count = 0
    
    with signaling_state:
        # Lấy bản sao của tất cả dữ liệu signaling chưa được báo cáo
        for signal_type, data_list in signaling_store.items():
            all_signals[signal_type] = list(data_list)
            signaling_store[signal_type] = [] # Xóa sau khi đã lấy
            total_count += len(data_list)
    
    print(f"[Peer Server] Đã báo cáo {total_count} tín hiệu WebRTC mới.")
    send_http_response(conn, 200, "OK", all_signals)


# --- CÁC ROUTE TIN NHẮN CŨ (Đã loại bỏ conn.close()) ---

@app.route('/message', methods=['POST'])
def listener(conn, name ,message): 
    """Xử lý tin nhắn nhận được."""
    with mess_state:
        message_mark["unread"].append((name, message))
    print(f"-> Đã nhận tin nhắn từ {name}: {message}")
    
    send_http_response(conn, 200, "OK", {"status": "ok", "message": "Message received"})
    # KHÔNG CÓ conn.close()

@app.route('/new_message', methods=['GET'])
def get_new_messages(conn, name, message):
    try:
        with mess_state:
            new_messages = message_mark['unread']
            messages_to_send = list(new_messages)
            
            message_mark['read'].extend(new_messages)
            message_mark['unread'] = [] 
            
        print(f"[Peer Server] Đã báo cáo {len(messages_to_send)} tin nhắn mới.")
        send_http_response(conn, 200, "OK", messages_to_send)
        
    except Exception as e:
        print(f"Lỗi khi xử lý /new_message: {e}", file=sys.stderr)
        send_http_response(conn, 500, "Internal Server Error", {"error": f"Internal Server Error: {e}"})
    # KHÔNG CÓ conn.close()
    
def handle_peer(conn, addr, routes):
    try:
        # Tăng kích thước buffer
        msg = conn.recv(8192).decode('utf-8') 
        if not msg:
            return

        # 1. PARSE REQUEST LINE (METHOD VÀ PATH)
        try:
            request_line = msg.split('\r\n')[0]
            method, full_path, _ = request_line.split(' ', 2)
            
            # Xử lý query params nếu có (ví dụ: /webrtc/poll?username=...)
            main_path = full_path.split('?')[0] 
            
            hooks = routes.get((method, main_path))
        except Exception as e:
            print(f"Lỗi parsing request line từ {addr}: {e}")
            send_http_response(conn, 400, "Bad Request", {"error": "Invalid request line format"})
            return
        
        # 2. Xử lý 404
        if not hooks:
            send_http_response(conn, 404, "Not Found", {"error": f"Route {main_path} not found for method {method}"})
            return
            
        # 3. PARSE BODY 
        raw_body_match = re.search(r'\r\n\r\n(.*)', msg, re.DOTALL)
        body = {}
        if raw_body_match:
            raw_body_str = raw_body_match.group(1).strip()
            try:
                body = json.loads(raw_body_str)
            except json.JSONDecodeError:
                print(f"Body từ {addr} không phải JSON hợp lệ.")
                
        message = body.get("message")
        name = body.get("name")
        
        # LẤY TOÀN BỘ BODY CHO SIGNALING
        signal_data = body 
        
        # 4. GỌI HOOKS VÀ TRUYỀN KẾT NỐI (conn, name, message/signal_data)
        # Nếu là route signaling, truyền signal_data. Nếu là route message, truyền message/name.
        if main_path.startswith('/webrtc'):
            hooks(conn, name, signal_data) # Truyền toàn bộ body JSON cho signaling
        else:
            hooks(conn, name, message) # Truyền name/message cho messaging

    except Exception as e:
        print(f"Lỗi xử lý kết nối: {e}", file=sys.stderr)
        # Gửi lỗi 500 nếu chưa gửi phản hồi
        if not conn._closed:
            send_http_response(conn, 500, "Internal Server Error", {"error": "Internal server error occurred during handling"})
    finally:
        # 5. Đóng kết nối tại đây.
        try:
            conn.close()
        except socket.error:
            pass 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port

    app.prepare_address(ip, port)
    app.run_backend()