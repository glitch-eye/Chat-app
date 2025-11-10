import argparse
from p2p_peer import P2PPeer, parse_peer

def main():
    ap = argparse.ArgumentParser(description="Tiny P2P peer (no server) — full-duplex chat")
    ap.add_argument("--nick", required=True)
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, required=True)
    ap.add_argument("--advertise-host", default=None)
    ap.add_argument("--peers", default="", help="Seed peers: '10.0.0.2:5002,10.0.0.3:5003'")
    ap.add_argument("--single-ip", action="store_true", help="Enforce one connection per remote IP")
    args = ap.parse_args()

    p = P2PPeer(
        nick=args.nick,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        advertise_host=args.advertise_host,
        single_connection_per_ip=args.single_ip,
    )
    p.start()

    # Seed connect
    if args.peers.strip():
        for item in args.peers.split(","):
            hp = parse_peer(item)
            if not hp:
                continue
            h, prt = hp
            p.connect_to(h, prt)

    print("=" * 60)
    print(f"Peer '{p.nick}' up at {p.peer_id}")
    print("Commands:")
    print("  <text>                 -> broadcast")
    print("  /peers                 -> list peers")
    print("  /send ip:port text     -> direct send")
    print("  /add-list              -> show local online list")
    print("  /quit                  -> exit")
    print("=" * 60)

    try:
        while True:
            line = input().strip()
            if not line:
                continue
            if line == "/quit":
                break
            if line == "/peers":
                rows = p.list_peers()
                if not rows:
                    print("(no peers)")
                for pid, nick in rows:
                    print(f"- {pid} ({nick or 'unknown'})")
                continue
            if line == "/add-list":
                rows = p.add_list()
                if not rows:
                    print("(empty)")
                for pid, nick in rows:
                    print(f"- {pid} ({nick})")
                continue
            if line.startswith("/send "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: /send ip:port message")
                    continue
                to_pid = parts[1].strip()
                msg = parts[2]
                p.send_to(to_pid, {"type": "msg", "from": p.peer_id, "nick": p.nick, "msg": msg})
                continue

            p.broadcast({"type": "msg", "from": p.peer_id, "nick": p.nick, "msg": line})
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        p.stop()
        print("Bye.")

if __name__ == "__main__":
    main()
