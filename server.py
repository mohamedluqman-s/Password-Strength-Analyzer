"""
==============================================================================
PASSWORD STRENGTH ANALYZER - ZERO-DEPENDENCY PYTHON HTTP SERVER
Thiranex Cyber Security Internship Project
==============================================================================
Description:
Runs a local HTTP server using only Python's standard library (no pip required).
Injects cybersecurity HTTP response headers and serves the web application.

Usage:
    python server.py
==============================================================================
"""

import http.server
import socketserver
import os
import sys

PORT = int(os.environ.get("PORT", 8000))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class CyberSecurityHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler that adds OWASP cybersecurity headers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # OWASP Security Headers
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

    def log_message(self, format, *args):
        # Clean logging format without leaking request bodies
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


def run():
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("127.0.0.1", PORT), CyberSecurityHTTPRequestHandler) as httpd:
        print("=" * 65)
        print("  PASSWORD STRENGTH ANALYZER - PYTHON LOCAL SERVER")
        print("  Thiranex Cyber Security Internship")
        print(f"  Serving at: http://127.0.0.1:{PORT}")
        print("  Open this URL in any web browser to view the application.")
        print("  Press Ctrl+C to stop.")
        print("=" * 65)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped gracefully.")


if __name__ == "__main__":
    run()

