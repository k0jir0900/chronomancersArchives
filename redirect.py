import os
from http.server import HTTPServer, BaseHTTPRequestHandler

port = os.environ.get('HTTPS_PORT', '5001')

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host', '').split(':')[0]
        self.send_response(301)
        self.send_header('Location', f'https://{host}:{port}{self.path}')
        self.end_headers()

    def do_POST(self):
        self.do_GET()

    def log_message(self, *args):
        pass

HTTPServer(('0.0.0.0', 80), RedirectHandler).serve_forever()
