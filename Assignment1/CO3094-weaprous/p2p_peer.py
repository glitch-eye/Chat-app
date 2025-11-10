import json
import socket
import threading
import random
from typing import Dict, Tuple, Optional

LINE_DELIM = b"\n"
RECV_BUFSZ = 4096
CONNECT_TIMEOUT = 3.0


def make_peer_id(host: str, port: int) -> str:
    return f"{host}:{port}"


def parse_peer(s: str) -> Optional[Tuple[str, int]]:
    s = s.strip()
    if not s:
        return None
    parts = s.split(":")
    if len(parts) != 2:
        return None
    host = parts[0].strip()
    try:
        port = int(parts[1].strip())
    except ValueError:
        return None
    return host, port


class ReaderThread(threading.Thread):
    """Đọc từng dòng JSON từ socket và chuyển cho on_message(peer_id, obj)."""
    daemon = True

    def __init__(self, sock: socket.socket, peer_id: str, on_message):
        super().__init__(name=f"Reader-{peer_id}")
        self.sock = sock
        self.peer_id = peer_id  # có thể update khi đã biết canonical id
        self.on_message = on_message
        self._stop_evt = threading.Event()
        self.buffer = b""

    def set_peer_id(self, new_id: str):
        self.peer_id = new_id
        try:
            self.name = f"Reader-{new_id}"
        except Exception:
            pass

    def stop(self):
        self._stop_evt.set()
        try:
            self.sock.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def run(self):
        try:
            while not self._stop_evt.is_set():
                chunk = self.sock.recv(RECV_BUFSZ)
                if not chunk:
                    break
                self.buffer += chunk
                while True:
                    idx = self.buffer.find(LINE_DELIM)
                    if idx == -1:
                        break
                    line = self.buffer[:idx]
                    self.buffer = self.buffer[idx + 1:]
                    if not line:
                        continue
                    try:
                        obj = json.loads(line.decode("utf-8", errors="ignore"))
                    except Exception:
                        continue
                    self.on_message(self.peer_id, obj)
        except Exception:
            pass
        finally:
            self.on_message(self.peer_id, {"type": "disconnect"})


class P2PPeer:
    def __init__(
        self,
        nick: str,
        listen_host: str,
        listen_port: int,
        advertise_host: Optional[str] = None,
        *,
        single_connection_per_ip: bool = False,
    ):
        self.nick = nick
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.advertise_host = advertise_host or listen_host
        self.peer_id = make_peer_id(self.advertise_host, self.listen_port)

        self.node_nonce = random.getrandbits(64)

        self.single_connection_per_ip = single_connection_per_ip

        self._lsock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None

        # Kết nối canonical: remote_id -> (socket, reader_thread, meta)
        self._conns: Dict[str, Tuple[socket.socket, ReaderThread, dict]] = {}
        # Kết nối tạm (chưa canonical): temp_id -> (socket, reader_thread, meta)
        self._pending: Dict[str, Tuple[socket.socket, ReaderThread, dict]] = {}

        # “add-list” nội bộ: peer_id -> display_name
        self._online: Dict[str, str] = {}

        # tên hiển thị đã phân biệt (nick#xxxx) theo remote_nonce
        self._display_names: Dict[str, str] = {}

        # chống socket trùng: (fileno, laddr, lport, raddr, rport)
        self._sock_guard = set()

        # one-IP-one-conn (nếu bật): ip -> remote_id đang giữ
        self._ip_owner: Dict[str, str] = {}

        self._lock = threading.Lock()
        self.on_app_message = self._default_on_app_message

    # ---------- Helpers ----------
    def _sock_key(self, sock: socket.socket) -> tuple:
        try:
            laddr, lport = sock.getsockname()
            raddr, rport = sock.getpeername()
            return (sock.fileno(), laddr, lport, raddr, rport)
        except Exception:
            return (sock.fileno(), None, None, None, None)

    def _display_name_for(self, nick: str, remote_nonce: Optional[int]) -> str:
        if remote_nonce is None:
            return nick
        return f"{nick}#{remote_nonce % 10000:04d}"

    # ---------- Lifecycle ----------
    def start(self):
        self._start_listener()
        print(f"[peer] '{self.nick}' at {self.peer_id} (nonce={self.node_nonce})")

    def stop(self):
        with self._lock:
            for _, (sock, rth, _) in list(self._pending.items()):
                try:
                    rth.stop()
                except Exception:
                    pass
                try:
                    key = self._sock_key(sock)
                    self._sock_guard.discard(key)
                    sock.close()
                except Exception:
                    pass
            self._pending.clear()

            for _, (sock, rth, _) in list(self._conns.items()):
                try:
                    rth.stop()
                except Exception:
                    pass
                try:
                    key = self._sock_key(sock)
                    self._sock_guard.discard(key)
                    sock.close()
                except Exception:
                    pass
            self._conns.clear()
            self._online.clear()
            self._display_names.clear()
            self._ip_owner.clear()

        if self._lsock:
            try:
                self._lsock.close()
            except Exception:
                pass
        if self._accept_thread and self._accept_thread.is_alive():
            try:
                self._accept_thread.join(timeout=1.0)
            except Exception:
                pass

    # ---------- Listener ----------
    def _start_listener(self):
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind((self.listen_host, self.listen_port))
        self._lsock.listen(64)

        def _accept_loop():
            while True:
                try:
                    conn, addr = self._lsock.accept()
                except OSError:
                    break

                key = self._sock_key(conn)
                with self._lock:
                    if key in self._sock_guard:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    self._sock_guard.add(key)

                remote_host, remote_port = addr[0], addr[1]
                temp_id = make_peer_id(remote_host, remote_port)
                rth = ReaderThread(conn, temp_id, self._on_raw_message)
                with self._lock:
                    self._pending[temp_id] = (conn, rth, {
                        "hello": None,
                        "direction": "incoming",
                        "remote_nonce": None
                    })
                rth.start()

                self._send_raw(conn, {
                    "type": "hello",
                    "from": self.peer_id,
                    "nick": self.nick,
                    "nonce": self.node_nonce
                })

        self._accept_thread = threading.Thread(target=_accept_loop, name=f"Acceptor-{self.listen_port}", daemon=True)
        self._accept_thread.start()

    # ---------- Outgoing connects ----------
    def connect_to(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            sock.connect((host, port))
            sock.settimeout(None)  
        except Exception as e:
            print(f"[connect] Cannot connect {host}:{port} - {e}")
            try:
                sock.close()
            except Exception:
                pass
            return

        # chống socket trùng
        key = self._sock_key(sock)
        with self._lock:
            if key in self._sock_guard:
                try:
                    sock.close()
                except Exception:
                    pass
                return
            self._sock_guard.add(key)

        temp_id = make_peer_id(host, port)
        rth = ReaderThread(sock, temp_id, self._on_raw_message)
        with self._lock:
            self._pending[temp_id] = (sock, rth, {
                "hello": None,
                "direction": "outgoing",
                "remote_nonce": None
            })
        rth.start()

        self._send_raw(sock, {
            "type": "hello",
            "from": self.peer_id,
            "nick": self.nick,
            "nonce": self.node_nonce
        })

    # ---------- Messaging ----------
    def _send_raw(self, sock: socket.socket, obj: dict):
        try:
            data = json.dumps(obj).encode("utf-8") + LINE_DELIM
            sock.sendall(data)
        except Exception:
            pass

    def send_to(self, peer_id: str, obj: dict):
        with self._lock:
            entry = self._conns.get(peer_id)
        if not entry:
            print(f"[send_to] Not connected: {peer_id}")
            return
        sock, _, _ = entry
        self._send_raw(sock, obj)

    def broadcast(self, obj: dict):
        with self._lock:
            items = list(self._conns.items())
        for pid, (sock, _, _) in items:
            self._send_raw(sock, obj)

    # ---------- Inbound processing ----------
    def _on_raw_message(self, temp_or_peer_id: str, obj: dict):
        if not isinstance(obj, dict):
            return

        typ = obj.get("type")

        if typ == "disconnect":
            with self._lock:
                if temp_or_peer_id in self._pending:
                    sock, rth, meta = self._pending.pop(temp_or_peer_id)
                    try:
                        rth.stop()
                    except Exception:
                        pass
                    try:
                        key = self._sock_key(sock)
                        self._sock_guard.discard(key)
                        sock.close()
                    except Exception:
                        pass
                else:
                    if temp_or_peer_id in self._conns:
                        sock, rth, meta = self._conns.pop(temp_or_peer_id)
                        try:
                            rth.stop()
                        except Exception:
                            pass
                        try:
                            key = self._sock_key(sock)
                            self._sock_guard.discard(key)
                            try:
                                ip = sock.getpeername()[0]
                                if self._ip_owner.get(ip) == temp_or_peer_id:
                                    self._ip_owner.pop(ip, None)
                            except Exception:
                                pass
                            sock.close()
                        except Exception:
                            pass
                        self._online.pop(temp_or_peer_id, None)
                        self._display_names.pop(temp_or_peer_id, None)
            print(f"[conn] Disconnected: {temp_or_peer_id}")
            return

        if typ == "hello":
            remote_id = obj.get("from") 
            nick = obj.get("nick", "Unknown")
            remote_nonce = obj.get("nonce", None)
            if not remote_id:
                return

            if remote_id == self.peer_id:
                with self._lock:
                    if temp_or_peer_id in self._pending:
                        sock, rth, _ = self._pending.pop(temp_or_peer_id)
                        try:
                            rth.stop()
                        except Exception:
                            pass
                        try:
                            key = self._sock_key(sock)
                            self._sock_guard.discard(key)
                            sock.close()
                        except Exception:
                            pass
                print("[conn] ignore self-connect")
                return

            display = self._display_name_for(nick, remote_nonce)

            with self._lock:
                entry = self._pending.pop(temp_or_peer_id, None)
                if not entry:
                    if remote_id in self._conns:
                        sock, rth, meta = self._conns[remote_id]
                        meta["hello"] = {"peer_id": remote_id, "nick": nick}
                        meta["remote_nonce"] = remote_nonce
                        self._display_names[remote_id] = display
                        self._online[remote_id] = display
                    return

                sock, rth, meta = entry
                meta["hello"] = {"peer_id": remote_id, "nick": nick}
                meta["remote_nonce"] = remote_nonce

                if self.single_connection_per_ip:
                    try:
                        ip = sock.getpeername()[0]
                    except Exception:
                        ip = None

                    if ip:
                        owner_id = self._ip_owner.get(ip)
                        if owner_id and owner_id != remote_id:
                            existed = self._conns.get(owner_id)
                            if existed:
                                keep_new = self._decide_keep_new(remote_id, new_meta=meta, existed_meta=existed[2])
                                if keep_new:
                                    old_sock, old_rth, _ = existed
                                    try:
                                        old_rth.stop()
                                    except Exception:
                                        pass
                                    try:
                                        key_old = self._sock_key(old_sock)
                                        self._sock_guard.discard(key_old)
                                        old_sock.close()
                                    except Exception:
                                        pass
                                    self._conns.pop(owner_id, None)
                                    self._online.pop(owner_id, None)
                                    self._display_names.pop(owner_id, None)
                                    self._ip_owner[ip] = remote_id
                                else:
                                    try:
                                        rth.stop()
                                    except Exception:
                                        pass
                                    try:
                                        key_new = self._sock_key(sock)
                                        self._sock_guard.discard(key_new)
                                        sock.close()
                                    except Exception:
                                        pass
                                    return
                            else:
                                self._ip_owner[ip] = remote_id
                        else:
                            self._ip_owner[ip] = remote_id

                existed = self._conns.get(remote_id)
                if existed:
                    keep_new = self._decide_keep_new(remote_id, new_meta=meta, existed_meta=existed[2])
                    if keep_new:
                        old_sock, old_rth, _ = existed
                        try:
                            old_rth.stop()
                        except Exception:
                            pass
                        try:
                            key_old = self._sock_key(old_sock)
                            self._sock_guard.discard(key_old)
                            old_sock.close()
                        except Exception:
                            pass
                        self._conns[remote_id] = (sock, rth, meta)
                        rth.set_peer_id(remote_id)
                    else:
                        # giữ kết nối cũ, đóng cái mới
                        try:
                            rth.stop()
                        except Exception:
                            pass
                        try:
                            key_new = self._sock_key(sock)
                            self._sock_guard.discard(key_new)
                            sock.close()
                        except Exception:
                            pass
                        return
                else:
                    # chưa có -> đăng ký canonical
                    self._conns[remote_id] = (sock, rth, meta)
                    rth.set_peer_id(remote_id)

                self._display_names[remote_id] = display
                self._online[remote_id] = display

            print(f"[conn] Hello from {remote_id} (nick={display})")
            self._send_raw(sock, {
                "type": "hello-ack",
                "from": self.peer_id,
                "nick": self.nick
            })
            return

        if typ == "hello-ack":
            frm = obj.get("from")
            nick = obj.get("nick", "Unknown")
            if frm:
                with self._lock:
                    self._display_names.setdefault(frm, nick)
                    self._online[frm] = self._display_names.get(frm, nick)
            return

        # App data
        self.on_app_message(temp_or_peer_id, obj)

    def _decide_keep_new(self, remote_id: str, new_meta: dict, existed_meta: dict) -> bool:
        """
        True → giữ kết nối mới; False → giữ kết nối cũ.
        Quy tắc:
          - Tạo tuple so sánh: (self_id, self_nonce) so sánh với (remote_id, remote_nonce)
          - Peer có tuple “lớn” thì ưu tiên giữ kết nối OUTGOING (chủ động)
          - Nếu cùng hướng, giữ kết nối cũ (tránh flap)
        """
        self_tuple = (self.peer_id, self.node_nonce)
        remote_tuple = (remote_id, new_meta.get("remote_nonce", -1))
        prefer_outgoing = self_tuple > remote_tuple

        new_is_out = (new_meta.get("direction") == "outgoing")
        old_is_out = (existed_meta.get("direction") == "outgoing")

        if new_is_out == old_is_out:
            return False 

        return new_is_out if prefer_outgoing else (not new_is_out)

    # ---------- App callback ----------
    def _default_on_app_message(self, peer_id: str, obj: dict):
        msg = obj.get("msg")
        frm = obj.get("from")
        if msg is not None:
            who = frm or peer_id
            print(f"[msg] {who}: {msg}")
        else:
            print(f"[msg] {peer_id}: {obj}")

    # ---------- Introspection ----------
    def list_peers(self):
        rows = []
        with self._lock:
            for pid, (_, __, meta) in self._conns.items():
                nick = self._display_names.get(pid) or (meta.get("hello") or {}).get("nick")
                rows.append((pid, nick))
        return rows

    def add_list(self):
        with self._lock:
            return sorted(self._online.items(), key=lambda x: x[0])
