"""
Privacy-Preserving Cloud File Storage
=====================================
Main Flask Application Server
-----------------------------
A full-stack secure cloud storage application featuring:
- AES-256-GCM authenticated encryption before cloud storage
- SHA-256 integrity verification
- bcrypt password hashing
- AWS S3 & local encrypted storage modes
- Fine-grained user-to-user sharing & expiring share links
- Comprehensive immutable security audit logging
"""

import os
from flask import Flask, render_template, send_from_directory, jsonify
from config import Config
from database import get_database

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.file_routes import file_bp
from routes.share_routes import share_bp
from routes.audit_routes import audit_bp

def create_app():
    """Application factory for Privacy-Preserving Cloud File Storage."""
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )
    
    # Load configuration
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    
    # Initialize database connection on startup
    with app.app_context():
        get_database()
    
    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(share_bp)
    app.register_blueprint(audit_bp)
    
    # Web UI Routes
    @app.route("/")
    def index():
        return render_template("index.html")
        
    @app.route("/share/<token>")
    def public_share_page(token):
        return render_template("shared_link.html", token=token)
        
    # Error Handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({
            "success": False,
            "error": "File size exceeds the permitted limit (Max: 50MB)."
        }), 413

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "The requested resource was not found."
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "success": False,
            "error": "An internal server error occurred."
        }), 500
        
    return app

if __name__ == "__main__":
    app = create_app()
    print(f"[*] Privacy-Preserving Cloud File Storage is starting on port {Config.PORT}...")
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)
