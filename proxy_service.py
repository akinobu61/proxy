import time
import logging
import urllib.parse
from functools import wraps
from flask import Blueprint, request, Response, jsonify, current_app
import requests
from bs4 import BeautifulSoup
import threading
from utils import obfuscate_url, deobfuscate_url, is_valid_url

logger = logging.getLogger(__name__)

proxy_blueprint = Blueprint('proxy', __name__, url_prefix='/api')

# Simple in-memory rate limiting
rate_limit_data = {
    'requests': {},
    'window_size': 60,  # seconds
    'max_requests': 60  # requests per window
}

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = time.time()
        
        # Clean up old entries
        for ip in list(rate_limit_data['requests'].keys()):
            rate_limit_data['requests'][ip] = [
                timestamp for timestamp in rate_limit_data['requests'][ip] 
                if current_time - timestamp < rate_limit_data['window_size']
            ]
            if not rate_limit_data['requests'][ip]:
                del rate_limit_data['requests'][ip]
        
        # Add current request
        if client_ip not in rate_limit_data['requests']:
            rate_limit_data['requests'][client_ip] = []
        
        rate_limit_data['requests'][client_ip].append(current_time)
        
        # Check if rate limit exceeded
        if len(rate_limit_data['requests'][client_ip]) > rate_limit_data['max_requests']:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return jsonify({"error": "Rate limit exceeded", "status": 429}), 429
        
        return f(*args, **kwargs)
    
    return decorated_function

def proxy_request(url, method=None, headers=None, data=None, is_resource=False):
    """
    Forward a request to the target URL and return the response
    """
    if not is_valid_url(url):
        return jsonify({"error": "Invalid target URL", "status": 400}), 400
    
    if method is None:
        method = request.method
    
    # Prepare headers
    if headers is None:
        headers = {key: value for key, value in request.headers.items()
                  if key.lower() not in ['host', 'content-length']}
        
        # Adjust referer and origin headers to prevent cross-origin issues
        if 'referer' in headers:
            # Remove original referer to avoid leaking information
            del headers['referer']
            
        # Add accept-encoding header to ensure we get the right content
        headers['accept-encoding'] = 'identity'
    
    # Prepare request body
    if data is None:
        data = request.get_data()

    try:
        logger.debug(f"Proxying request to {url} with method {method}")
        
        # Forward the request to the target URL
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=request.args,
            stream=True,
            timeout=10,
            allow_redirects=False  # We'll handle redirects manually
        )
        
        # Process the response based on content type
        content_type = resp.headers.get('content-type', '')
        
        # Handle HTML content - we need to rewrite links
        if 'text/html' in content_type:
            try:
                content = resp.content.decode('utf-8', errors='replace')
                
                # Get base URL for resolving relative URLs
                parsed_url = urllib.parse.urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                # Replace relative URLs with absolute ones for proxy
                # This is a simple implementation and might need enhancement for complex pages
                soup = BeautifulSoup(content, 'html.parser')
                
                # Process all links
                for link in soup.find_all(['a', 'link']):
                    href = link.get('href')
                    if href:
                        # Skip fragment-only links (e.g., #section)
                        if href.startswith('#'):
                            continue
                            
                        # Handle relative URLs
                        if href.startswith('/'):
                            absolute_url = f"{base_url}{href}"
                        # Handle absolute URLs
                        elif href.startswith(('http://', 'https://')):
                            absolute_url = href
                        # Handle protocol-relative URLs (//example.com)
                        elif href.startswith('//'):
                            absolute_url = f"{parsed_url.scheme}:{href}"
                        else:
                            # Skip mailto:, tel:, javascript: links
                            if any(href.startswith(scheme) for scheme in ['mailto:', 'tel:', 'javascript:']):
                                continue
                            # Other relative paths (not starting with /)
                            path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                            absolute_url = f"{base_url}{path_base}/{href}"
                        
                        # Obfuscate and create proxy URL
                        obfuscated = obfuscate_url(absolute_url)
                        if obfuscated:
                            proxy_url = f"/api/proxy/{obfuscated}"
                            link['href'] = proxy_url
                
                # Process all scripts, images, and other resources
                for tag in soup.find_all(['script', 'img', 'iframe', 'source']):
                    src = tag.get('src')
                    if src and not src.startswith('data:'):  # Skip data: URLs
                        # Handle relative URLs
                        if src.startswith('/'):
                            absolute_url = f"{base_url}{src}"
                        # Handle absolute URLs
                        elif src.startswith(('http://', 'https://')):
                            absolute_url = src
                        # Handle protocol-relative URLs (//example.com)
                        elif src.startswith('//'):
                            absolute_url = f"{parsed_url.scheme}:{src}"
                        else:
                            # Other relative paths (not starting with /)
                            path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                            absolute_url = f"{base_url}{path_base}/{src}"
                        
                        # Obfuscate and create proxy URL
                        obfuscated = obfuscate_url(absolute_url)
                        if obfuscated:
                            proxy_url = f"/api/proxy/{obfuscated}"
                            tag['src'] = proxy_url
                
                # Process inline styles with URLs (background-image, etc.)
                for tag in soup.find_all(style=True):
                    style = tag.get('style')
                    if 'url(' in style:
                        # Find all URLs in style attribute
                        import re
                        url_pattern = r'url\([\'"]?(.*?)[\'"]?\)'
                        for match in re.finditer(url_pattern, style):
                            original_url = match.group(1)
                            
                            # Skip data: URLs
                            if original_url.startswith('data:'):
                                continue
                                
                            # Handle different URL types
                            if original_url.startswith('/'):
                                absolute_url = f"{base_url}{original_url}"
                            elif original_url.startswith(('http://', 'https://')):
                                absolute_url = original_url
                            elif original_url.startswith('//'):
                                absolute_url = f"{parsed_url.scheme}:{original_url}"
                            else:
                                path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                                absolute_url = f"{base_url}{path_base}/{original_url}"
                            
                            # Obfuscate and create proxy URL
                            obfuscated = obfuscate_url(absolute_url)
                            if obfuscated:
                                proxy_url = f"/api/proxy/{obfuscated}"
                                style = style.replace(f"url({original_url})", f"url({proxy_url})")
                                
                        # Update the style attribute
                        tag['style'] = style
                
                # Process meta refresh tags and redirects
                for meta in soup.find_all('meta', attrs={'http-equiv': True}):
                    if meta['http-equiv'].lower() == 'refresh' and 'content' in meta.attrs:
                        content = meta['content']
                        if 'url=' in content.lower():
                            parts = content.split(';', 1)
                            delay = parts[0]
                            url_part = parts[1].strip()
                            url_index = url_part.lower().find('url=')
                            if url_index >= 0:
                                original_url = url_part[url_index + 4:].strip('\'"')
                                
                                # Handle different URL types
                                if original_url.startswith('/'):
                                    absolute_url = f"{base_url}{original_url}"
                                elif original_url.startswith(('http://', 'https://')):
                                    absolute_url = original_url
                                elif original_url.startswith('//'):
                                    absolute_url = f"{parsed_url.scheme}:{original_url}"
                                else:
                                    path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                                    absolute_url = f"{base_url}{path_base}/{original_url}"
                                
                                # Obfuscate and create proxy URL
                                obfuscated = obfuscate_url(absolute_url)
                                if obfuscated:
                                    proxy_url = f"/api/proxy/{obfuscated}"
                                    meta['content'] = f"{delay}; url={proxy_url}"
                
                # Convert back to string
                content = str(soup)
                
                # Create response with modified content
                response = Response(content, status=resp.status_code)
            except Exception as e:
                logger.error(f"Error processing HTML: {str(e)}")
                # Fall back to unmodified content
                response = Response(
                    response=resp.iter_content(chunk_size=1024),
                    status=resp.status_code
                )
        else:
            # For non-HTML content, stream the response as-is
            response = Response(
                response=resp.iter_content(chunk_size=1024),
                status=resp.status_code
            )
        
        # Copy headers from the proxied response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        for name, value in resp.headers.items():
            if name.lower() not in excluded_headers:
                response.headers[name] = value
                
        # Ensure proper content type with charset
        if 'content-type' in resp.headers:
            content_type = resp.headers['content-type']
            if 'text/html' in content_type and 'charset' not in content_type:
                response.headers['Content-Type'] = f"{content_type}; charset=utf-8"
            else:
                response.headers['Content-Type'] = content_type
        
        return response
    
    except requests.exceptions.Timeout:
        logger.error(f"Request to {url} timed out")
        return jsonify({"error": "Request to target URL timed out", "status": 504}), 504
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error proxying request to {url}: {str(e)}")
        return jsonify({"error": f"Error proxying request: {str(e)}", "status": 502}), 502

# ウェイト時間を追加（秒）
DEFAULT_WAIT_TIME = 1  

@proxy_blueprint.route('/proxy/<path:obfuscated_url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@rate_limit
def proxy_endpoint(obfuscated_url):
    """
    Main proxy endpoint that accepts an obfuscated URL and forwards the request
    """
    try:
        # Deobfuscate the URL
        target_url = deobfuscate_url(obfuscated_url)
        if not target_url:
            return jsonify({"error": "Invalid obfuscated URL", "status": 400}), 400
        
        # クエリパラメータからウェイト時間を取得（指定がなければデフォルト値を使用）
        wait_time = request.args.get('wait', DEFAULT_WAIT_TIME, type=float)
        
        logger.info(f"Proxying request to {target_url} with {wait_time}s delay")
        
        # 指定された時間だけウェイト
        if wait_time > 0:
            time.sleep(wait_time)
        
        return proxy_request(target_url)
    
    except Exception as e:
        logger.error(f"Error in proxy_endpoint: {str(e)}")
        return jsonify({"error": f"Proxy error: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/obfuscate', methods=['POST'])
@rate_limit
def obfuscate_endpoint():
    """
    API endpoint to obfuscate a URL
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required", "status": 400}), 400
    
    url = data['url']
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL", "status": 400}), 400
    
    try:
        obfuscated = obfuscate_url(url)
        proxy_url = f"{request.url_root.rstrip('/')}/api/proxy/{obfuscated}"
        
        return jsonify({
            "original_url": url,
            "obfuscated_url": obfuscated,
            "proxy_url": proxy_url
        })
    
    except Exception as e:
        logger.error(f"Error in obfuscate_endpoint: {str(e)}")
        return jsonify({"error": f"Obfuscation error: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/search', methods=['GET', 'POST'])
@rate_limit
def search_endpoint():
    """
    Special endpoint for search engines like Whoogle
    This endpoint mimics the Google search API structure while proxying through our service
    """
    try:
        # Default search engine URL (Google)
        search_base_url = "https://www.google.com/search"
        
        # Process query parameters
        if request.method == 'GET':
            query_params = request.args.to_dict(flat=False)
        else:  # POST
            query_params = request.form.to_dict(flat=False)
        
        # Build the target URL with query parameters
        query_string = urllib.parse.urlencode(query_params, doseq=True)
        target_url = f"{search_base_url}?{query_string}"
        
        # Check if it's a valid URL
        if not is_valid_url(target_url):
            return jsonify({"error": "Invalid search URL", "status": 400}), 400
        
        # クエリパラメータからウェイト時間を取得（指定がなければデフォルト値を使用）
        wait_time = request.args.get('wait', DEFAULT_WAIT_TIME, type=float)
        
        logger.info(f"Proxying search request to {target_url} with {wait_time}s delay")
        
        # 指定された時間だけウェイト
        if wait_time > 0:
            time.sleep(wait_time)
        
        # Custom headers for search engines
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
        
        # Handle POST data if present
        data = request.get_data() if request.method == 'POST' else None
        
        # Proxy the request
        return proxy_request(target_url, method=request.method, headers=headers, data=data)
    
    except Exception as e:
        logger.error(f"Error in search_endpoint: {str(e)}")
        return jsonify({"error": f"Search error: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/direct_url', methods=['GET'])
@rate_limit
def direct_url_endpoint():
    """
    Endpoint to directly access a URL provided as a parameter
    """
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({"error": "URL parameter is required", "status": 400}), 400
        
        if not is_valid_url(url):
            return jsonify({"error": "Invalid URL", "status": 400}), 400
        
        # クエリパラメータからウェイト時間を取得（指定がなければデフォルト値を使用）
        wait_time = request.args.get('wait', DEFAULT_WAIT_TIME, type=float)
        
        # 指定された時間だけウェイト
        if wait_time > 0:
            logger.info(f"Waiting for {wait_time}s before processing direct URL request")
            time.sleep(wait_time)
        
        # Obfuscate the URL and redirect to the proxy endpoint
        obfuscated = obfuscate_url(url)
        if not obfuscated:
            return jsonify({"error": "Failed to process URL", "status": 500}), 500
        
        proxy_url = f"/api/proxy/{obfuscated}"
        return jsonify({"proxy_url": proxy_url})
    
    except Exception as e:
        logger.error(f"Error in direct_url_endpoint: {str(e)}")
        return jsonify({"error": f"Error processing URL: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({"status": "ok"})
