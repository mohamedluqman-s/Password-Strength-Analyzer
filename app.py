"""
==============================================================================
PASSWORD STRENGTH ANALYZER - FLASK WEB SERVER
Thiranex Cyber Security Internship Project
==============================================================================
Description:
A lightweight Flask server to host the Password Strength Analyzer with
hardened cybersecurity HTTP security headers (OWASP Secure Headers).

Architecture Note:
Password analysis is performed 100% locally in the client's browser (V8 engine)
to preserve zero-knowledge security and privacy. The backend deliberately
does NOT provide any password transmission or analysis endpoints so cleartext
credentials NEVER traverse the network or server logs.
==============================================================================
"""

import os
from flask import Flask, send_from_directory, jsonify

# Initialize Flask app pointing to root static directory
app = Flask(__name__, static_folder=".", static_url_path="")

# Disable debug banner and secure configurations
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def apply_security_headers(response):
    """
    Applies enterprise-grade HTTP security headers aligned with
    OWASP and CIS benchmarks to harden the client environment.
    """
    # Restrict resource origins to self
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
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # XSS Protection filter for legacy browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Referrer privacy
    response.headers["Referrer-Policy"] = "no-referrer"
    # Restrict browser APIs (camera, microphone, geolocation)
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )
    # Cache control for security
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.route("/")
def serve_index():
    """Serves the main application homepage."""
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serves static assets (CSS, JS, assets)."""
    return send_from_directory(".", path)


@app.route("/api/security-audit-info", methods=["GET"])
def security_audit_info():
    """
    Informational endpoint confirming zero-knowledge architecture.
    Does NOT accept or handle passwords.
    """
    return jsonify({
        "status": "active",
        "project": "Password Strength Analyzer",
        "internship": "Thiranex Cyber Security Internship",
        "architecture": "Zero-Knowledge Client-Side Evaluation",
        "telemetry_policy": "No credential ingestion, storage, or logging."
    })


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5000))
    print("=" * 65)
    print("  PASSWORD STRENGTH ANALYZER - CYBERSECURITY SERVER")
    print("  Thiranex Cyber Security Internship")
    print(f"  Running on: http://127.0.0.1:{PORT}")
    print("  Zero-Knowledge Security Active: Local Client Analysis Only")
    print("=" * 65)
    app.run(host="127.0.0.1", port=PORT, debug=True)

