"""
==============================================================================
PASSWORD STRENGTH ANALYZER - FLASK WEB SERVER
Thiranex Cyber Security Internship Project
==============================================================================
Description:
A lightweight Flask server to host the Password Strength Analyzer with
hardened cybersecurity HTTP security headers (OWASP Secure Headers).
==============================================================================
"""

import os
from flask import Flask, send_from_directory, jsonify

# Base project directory is parent
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(BASE_DIR, path)


@app.route("/api/security-audit-info", methods=["GET"])
def security_audit_info():
    return jsonify({
        "status": "active",
        "project": "Password Strength Analyzer",
        "internship": "Thiranex Cyber Security Internship",
        "architecture": "Zero-Knowledge Client-Side Evaluation"
    })


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5000))
    print(f"Running Flask server at: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=True)

