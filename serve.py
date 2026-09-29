import http.server
import re
import subprocess
import socket
import threading
import json
from pathlib import Path

PORT = 8000
ROOT = Path(__file__).resolve().parent
PAYLOADS_DIR = ROOT / "payloads"
PAYLOAD_FILES = [PAYLOADS_DIR / "kstuff.elf", PAYLOADS_DIR / "shadowmountplus.elf"]
TCP_PORT = 9021
RETRIES = 3
TIMEOUT = 10
CHUNK_SIZE = 4096

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_POST(self):
        # Autoloader endpoint
        if self.path == '/ready':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode() if length else ''
            data = {}
            try:
                data = json.loads(body) if body else {}
            except Exception:
                pass
            target_ip = data.get('ip') or self.client_address[0]
            session = data.get('session') or 'default'
            print(f"[autoloader] /ready from {self.client_address[0]} (session={session}) -> target {target_ip}")
            threading.Thread(target=send_sequence, args=(target_ip,)).start()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
            return
        # Fallback to static file serving
        return super().do_POST()


def send_sequence(ip, port=TCP_PORT):
    # Verify payloads exist before attempting
    for p in PAYLOAD_FILES:
        if not p.exists():
            print(f"[autoloader] missing payload: {p}")
            return

    for attempt in range(1, RETRIES + 1):
        try:
            print(f"[autoloader] connecting to {ip}:{port} (attempt {attempt})")
            with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                for p in PAYLOAD_FILES:
                    print(f"[autoloader] streaming {p.name} -> {ip}:{port}")
                    with p.open("rb") as f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            s.sendall(chunk)
                print("[autoloader] all payloads streamed successfully")
                return
        except Exception as e:
            print(f"[autoloader] attempt {attempt} failed: {e}")
    print("[autoloader] all attempts failed")


def local_ip():
    output = subprocess.check_output(
        ["ipconfig"],
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    for ip in re.findall(r"IPv4[^:]*:\s*([\d.]+)", output):
        if ip.startswith("192.168."):
            return ip

    return "localhost"

if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as server:
        print(f"http://{local_ip()}:{PORT}/")
        server.serve_forever()
