import os
import logging
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Enable CORS
CORS(app)

# Import routes after app is created to avoid circular imports
from proxy_service import proxy_blueprint

# Register blueprints
app.register_blueprint(proxy_blueprint)

# Home route - redirect to API info
@app.route('/')
def index():
    return jsonify({
        "api": "Proxy API Service",
        "version": "1.0",
        "description": "URL obfuscation and proxy service",
        "endpoints": {
            "/api/obfuscate": "POST - Obfuscate a URL",
            "/api/proxy/{obfuscated_url}": "GET/POST/etc - Access content through proxy",
            "/api/search": "GET - Search engine proxy",
            "/api/direct_url": "GET - Direct URL access"
        },
        "note": "URLs expire after 1 hour"
    })

# API Documentation - JSON format
@app.route('/docs')
def docs():
    return jsonify({
        "api_documentation": {
            "obfuscate_endpoint": {
                "url": "/api/obfuscate",
                "method": "POST",
                "body": {"url": "https://example.com"},
                "response": {
                    "original_url": "https://example.com",
                    "obfuscated_url": "encoded_string.checksum",
                    "proxy_url": "/api/proxy/encoded_string.checksum"
                }
            },
            "proxy_endpoint": {
                "url": "/api/proxy/{obfuscated_url}",
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                "parameters": {
                    "wait": "Seconds to wait before processing (default: 1, set to 0 for immediate)"
                }
            },
            "search_endpoint": {
                "url": "/api/search",
                "method": "GET",
                "parameters": {
                    "q": "Search query",
                    "wait": "Seconds to wait before processing (default: 1)"
                }
            },
            "direct_url_endpoint": {
                "url": "/api/direct_url",
                "method": "GET",
                "parameters": {
                    "url": "URL to access through proxy",
                    "wait": "Seconds to wait before processing (default: 1)"
                }
            }
        },
        "notes": [
            "All URLs expire after 1 hour",
            "Redirects are automatically followed",
            "Rate limiting: 60 requests per minute"
        ]
    })

# Error handlers - all JSON responses
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "Endpoint not found", "status": 404}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return jsonify({"error": "Internal server error", "status": 500}), 500

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Rate limit exceeded", "status": 429}), 429
