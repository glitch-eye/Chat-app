# start_servers.py
import argparse
import subprocess
import time
import signal
import sys
import os

DEFAULT_PROXY_IP = '0.0.0.0'
DEFAULT_PROXY_PORT = 8080
DEFAULT_BACKEND_IP = '0.0.0.0'
DEFAULT_BACKEND_PORT = 8000 

processes = []

def start_process(file_name, ip, port, role):
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
    processes.append(process)
    print(f"[{role}] PID: {process.pid}")
    return process

def cleanup_processes(signum=None, frame=None):
    """Đóng tất cả các tiến trình đang chạy."""
    print("\n[CLEANUP] 🚨 Đang đóng Proxy và Backend...")
    for p in processes:
        if p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
    print("[CLEANUP] ✅ Hoàn tất.")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_processes)
    
    parser = argparse.ArgumentParser(
        prog='start_servers', 
        description='Khởi chạy Proxy và Backend Server.',
    )
    parser.add_argument('--proxy-ip', default=DEFAULT_PROXY_IP)
    parser.add_argument('--proxy-port', type=int, default=DEFAULT_PROXY_PORT)
    parser.add_argument('--backend-ip', default=DEFAULT_BACKEND_IP)
    parser.add_argument('--backend-port', type=int, default=DEFAULT_BACKEND_PORT)
    args = parser.parse_args()
    
    try:
        # 1. Khởi chạy Backend Server
        start_process("start_sampleapp.py", args.backend_ip, args.backend_port, "BACKEND")
        time.sleep(1) 
        
        # 2. Khởi chạy Proxy Server
        start_process("start_proxy.py", args.proxy_ip, args.proxy_port, "PROXY")
        time.sleep(1) 

        print("\n[INFO] Cả Proxy và Backend đang chạy. Nhấn CTRL+C để dừng tất cả.")
        
        while True:
            time.sleep(1)
            if any(p.poll() is not None for p in processes):
                print("[ERROR] Một Server đã dừng đột ngột!")
                break
                
    except FileNotFoundError as e:
        print(f"\n[ERROR] ❌ Thiếu file: {e}. Đảm bảo các file Server tồn tại.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
        
    finally:
        cleanup_processes()