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

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# API Documentation route
@app.route('/docs')
def docs():
    return render_template('docs.html')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Endpoint not found", "status": 404}), 404
    return render_template('index.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({"error": "Internal server error", "status": 500}), 500
    return render_template('index.html', error="Internal server error"), 500

@app.errorhandler(429)
def too_many_requests(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Rate limit exceeded", "status": 429}), 429
    return render_template('index.html', error="Too many requests, please try again later"), 429
