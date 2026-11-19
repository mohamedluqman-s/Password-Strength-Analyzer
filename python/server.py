"""
==============================================================================
PASSWORD STRENGTH ANALYZER - PYTHON STANDARD LIBRARY SERVER
Thiranex Cyber Security Internship Project
==============================================================================
"""

import http.server
import socketserver
import os
import sys

PORT = int(os.environ.get("PORT", 8000))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CyberSecurityHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def end_headers(self):
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'none';"
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()


def run():
    os.chdir(BASE_DIR)
    with socketserver.TCPServer(("127.0.0.1", PORT), CyberSecurityHTTPRequestHandler) as httpd:
        print("=" * 65)
        print("  PASSWORD STRENGTH ANALYZER - PYTHON LOCAL SERVER")
        print("  Thiranex Cyber Security Internship")
        print(f"  Serving at: http://127.0.0.1:{PORT}")
        print("=" * 65)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped gracefully.")


if __name__ == "__main__":
    run()

