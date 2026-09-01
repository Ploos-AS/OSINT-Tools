import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("OSINT_TOOLS_HOST", "0.0.0.0")
PORT = int(os.environ.get("OSINT_TOOLS_PORT", "8080"))
DATA_DIR = os.environ.get("OSINT_TOOLS_DATA_DIR", "/data")

class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/api/v1/info":
            self._json(200, {
                "name": "OSINT Tools",
                "milestone": "M0",
                "data_dir": DATA_DIR,
                "passive_first": True,
            })
        else:
            self._json(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"OSINT Tools M0 listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
