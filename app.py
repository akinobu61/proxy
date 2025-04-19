import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, Response
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

# Enable CORS with expanded settings
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "allow_headers": ["Content-Type", "Authorization", "Accept", "X-Requested-With"],
        "expose_headers": ["Content-Length", "Content-Type", "X-Content-Type-Options"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Import routes after app is created to avoid circular imports
from proxy_service import proxy_blueprint

# Register blueprints
app.register_blueprint(proxy_blueprint)

# Discord特有の静的アセットのリダイレクト
@app.route('/<path:path>', methods=['GET'])
def discord_asset_redirect(path):
    """
    Discordアセットリダイレクトハンドラ
    """
    # 特定の拡張子を持つDiscordアセットへのリクエストをAPIルートにリダイレクト
    special_extensions = ['.js', '.wasm', '.woff2', '.svg', '.png', '.webp', '.css', '.ico', '.js.map', '.css.map']
    
    # 拡張子チェック
    has_special_ext = any(path.endswith(ext) for ext in special_extensions)
    
    print(f"Discord asset redirect request for path: {path}")

    # Discord API直接リクエスト
    if path.startswith('api/v') or 'gateway.discord.gg' in path or 'remote-auth-gateway.discord.gg' in path:
        print(f"Redirecting Discord API request directly to: {path}")
        # 特別なパス処理
        if 'gateway.discord.gg' in path:
            return redirect(f"https://{path}")
        elif 'remote-auth-gateway.discord.gg' in path:
            return redirect(f"https://{path}")
        else:
            return redirect(f"https://discord.com/{path}")
        
        # ディスコードAPI直接リダイレクト
    
    # api/assets/ への直接リクエストを処理（通常のリダイレクトでは対応できなかった場合の対処）
    if path.startswith('api/assets/'):
        asset_filename = path.replace('api/assets/', '', 1)
        # 空のJavaScriptやCSS、マップファイルを返す
        if asset_filename.endswith('.js'):
            print(f"空のJSファイルを返します: {asset_filename}")
            empty_js = "// Empty JS file\nconsole.log('Empty JS file provided');"
            response = Response(empty_js, mimetype='application/javascript')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'application/javascript'
            return response
        elif asset_filename.endswith('.css'):
            print(f"空のCSSファイルを返します: {asset_filename}")
            empty_css = "/* Empty CSS file */\n"
            response = Response(empty_css, mimetype='text/css')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'text/css'
            return response
        elif asset_filename.endswith('.map'):
            print(f"空のマップファイルを返します: {asset_filename}")
            empty_map = "{}"
            response = Response(empty_map, mimetype='application/json')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            # Discord CDNへ直接リダイレクト
            print(f"Direct assets redirect: {asset_filename}")
            return redirect(f"https://discord.com/assets/{asset_filename}")
    # 他のapi/で始まるパスは処理しない（再帰リダイレクト防止）
    elif path.startswith('api/'):
        return render_template('simple_index.html')
    
    # Discord API直接リクエスト
    if path.startswith('api/v') and 'discord.com' in request.host:
        api_path = path
        return redirect(f"https://discord.com/{api_path}")
    
    # assets/assetsの二重パス構造への対応
    if path.startswith('assets/assets/') and has_special_ext:
        actual_path = path.replace('assets/assets/', '', 1)
        print(f"Redirecting assets/assets/ path to /api/assets/{actual_path}")
        return redirect(f"/api/assets/{actual_path}")
    elif path.startswith('assets/') and has_special_ext:
        actual_path = path.replace('assets/', '', 1) 
        print(f"Redirecting assets/ path to /api/assets/{actual_path}")
        return redirect(f"/api/assets/{actual_path}")
    elif has_special_ext:
        # 通常のファイル
        print(f"Redirecting normal asset to /api/assets/{path}")
        return redirect(f"/api/assets/{path}")
    
    # デフォルトのルート（上記に当てはまらない場合はインデックスページに戻る）
    return render_template('simple_index.html')

# Home route - シンプルなホームページを表示
@app.route('/')
def index():
    return render_template('simple_index.html')

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
