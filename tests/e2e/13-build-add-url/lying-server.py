import http.server
import socketserver

BODY = b"downloaded-by-add\n"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/good":
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        elif self.path == "/short":
            # Claims a megabyte, hangs up after 4 KiB. A
            # Content-Length body that ends early raises
            # nothing in http.client, which is why the build
            # has to compare the counts itself.
            self.send_response(200)
            self.send_header("Content-Length", "1048576")
            self.end_headers()
            self.wfile.write(b"x" * 4096)
            self.close_connection = True
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("127.0.0.1", 8099), Handler).serve_forever()
