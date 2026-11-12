# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Mock registry and HTTP server for e2e network tests."""

import http.server
import socketserver
import threading

BASIC_AUTH = "Basic dXNlcjpwYXNz"

# Bodies are sent with their Content-Length: under HTTP/1.1 a client reads
# until the connection closes otherwise, and this server never closes one.
_ERR_429 = b'{"errors":[{"code":"TOOMANYREQUESTS"}]}'
_ERR_401 = b'{"errors":[{"code":"UNAUTHORIZED"}]}'
_ERR_401_BAD = b'{"errors":[{"code":"UNAUTHORIZED","message":"bad credentials"}]}'


def _send_body(handler, body: bytes) -> None:
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class MainRegistryHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        if "ratelimited" in self.path:
            self.send_response(429)
            self.send_header("Retry-After", "3600")
            self.send_header("RateLimit-Remaining", "0;w=3600")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            _send_body(self, b"OK\n")
        elif self.path == "/redirect/ftp":
            self.send_response(302)
            self.send_header("Location", "ftp://127.0.0.1/file.tar")
            self.end_headers()
        elif self.path == "/redirect/downgrade":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8097/payload")
            self.end_headers()
        elif self.path == "/payload":
            self.send_response(200)
            self.send_header("Content-Length", "14")
            self.end_headers()
            self.wfile.write(b"dummy-payload\n")
        elif "ratelimited" in self.path:
            self.send_response(429)
            self.send_header("Retry-After", "3600")
            self.send_header("RateLimit-Remaining", "0;w=3600")
            _send_body(self, _ERR_429)
        elif self.path.startswith("/v2/"):
            auth = self.headers.get("Authorization")
            if not auth:
                self.send_response(401)
                self.send_header("Www-Authenticate", 'Basic realm="mock-registry"')
                _send_body(self, _ERR_401)
            elif auth == BASIC_AUTH:
                self.send_response(200)
                _send_body(self, b"{}")
            else:
                self.send_response(401)
                self.send_header("Www-Authenticate", 'Basic realm="mock-registry"')
                _send_body(self, _ERR_401_BAD)
        else:
            self.send_error(404)

    def do_POST(self):
        if "ratelimited" in self.path:
            self.send_response(429)
            self.send_header("Retry-After", "3600")
            self.send_header("RateLimit-Remaining", "0;w=3600")
            _send_body(self, _ERR_429)
        elif "offorigin" in self.path:
            self.send_response(202)
            self.send_header("Location", "http://127.0.0.1:8096/upload/session1")
            self.send_header("Range", "0-0")
            self.send_header("Docker-Upload-UUID", "session1")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, *args):
        pass


class UploadHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_PUT(self):
        auth = self.headers.get("Authorization")
        with open("/tmp/token-test.result", "w") as fh:
            if auth:
                fh.write(f"LEAKED: {auth}\n")
            else:
                fh.write("STRIPPED\n")
        self.send_response(201)
        self.send_header("Location", "http://127.0.0.1:8096/upload/session1")
        self.send_header("Docker-Content-Digest", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.end_headers()

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


s2 = Server(("127.0.0.1", 8096), UploadHandler)
threading.Thread(target=s2.serve_forever, daemon=True).start()
Server(("127.0.0.1", 8097), MainRegistryHandler).serve_forever()
