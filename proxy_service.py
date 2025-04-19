import time
import logging
import urllib.parse
import traceback
from functools import wraps
from flask import Blueprint, request, Response, jsonify, current_app
import requests
from bs4 import BeautifulSoup
import threading
from utils import obfuscate_url, deobfuscate_url, is_valid_url
import re

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

        # サイト特有の設定
        if 'youtube.com' in url or 'googlevideo.com' in url:
            # YouTubeの動画ストリーミングのためにOriginとRefererを調整
            headers['Origin'] = 'https://www.youtube.com'
            headers['Referer'] = 'https://www.youtube.com/'
        elif 'discord.com' in url or 'discordapp.com' in url:
            # Discordのための特殊ヘッダー設定
            headers['Origin'] = 'https://discord.com'
            headers['Referer'] = 'https://discord.com/'
            # Discordアプリケーションでは一般的に使用される一部のヘッダーを追加
            headers['Sec-Fetch-Dest'] = 'empty'
            headers['Sec-Fetch-Mode'] = 'cors'
            headers['Sec-Fetch-Site'] = 'same-origin'
        else:
            # 他のサイトでは単にrefererを削除
            if 'referer' in headers:
                del headers['referer']

        # Add accept-encoding header to ensure we get the right content
        headers['accept-encoding'] = 'identity'

    # Prepare request body
    if data is None:
        data = request.get_data()

    try:
        logger.debug(f"Proxying request to {url} with method {method}")

        # タイムアウト設定
        request_timeout = 30
        if 'googlevideo.com' in url and 'videoplayback' in url:
            # YouTube動画は長めのタイムアウト
            request_timeout = 60
        elif 'discord.com' in url or 'discordapp.com' in url:
            # Discordリクエストも長めのタイムアウト
            request_timeout = 40

        # Forward the request to the target URL
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=request.args,
            stream=True,
            timeout=request_timeout,
            allow_redirects=True  # リダイレクト先のコンテンツまで処理するように変更（togetter等の対応）
        )

        # リダイレクトの処理はrequests.requestのallow_redirects=Trueに任せるため、
        # この手動リダイレクト処理コードは削除します
        # リダイレクト先の内容はresp.contentに含まれているので、以降の処理で通常通り処理されます

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

                # Process all links (a, link, area, base要素)
                for link in soup.find_all(['a', 'link', 'area', 'base']):
                    href = link.get('href')
                    if href:
                        # Skip fragment-only links, javascript, mailto and tel links
                        if href.startswith('#') or any(href.startswith(scheme) for scheme in ['javascript:', 'mailto:', 'tel:', 'data:']):
                            continue

                        try:
                            # 最終的なURLを正規化（基準URLからの相対パスを絶対URLに変換）
                            # 重要: リダイレクト後のURLを基準にする必要があるため、
                            # resp.urlを使用（リダイレクト後の最終URL）
                            final_url = resp.url
                            final_base_url = f"{urllib.parse.urlparse(final_url).scheme}://{urllib.parse.urlparse(final_url).netloc}"
                            
                            # URLの完全な正規化
                            normalized_url = urllib.parse.urljoin(final_url, href)
                            
                            # ログ出力（デバッグ用）
                            logger.debug(f"リンク正規化: {href} → {normalized_url}")

                            # URLを難読化
                            obfuscated_result = obfuscate_url(normalized_url)
                            if isinstance(obfuscated_result, dict):
                                obfuscated = obfuscated_result.get('obfuscated_url')
                            else:
                                obfuscated = obfuscated_result

                            if obfuscated:
                                proxy_url = create_proxy_url(obfuscated)
                                link['href'] = proxy_url

                                # onclick属性の処理
                                if link.has_attr('onclick'):
                                    onclick = link['onclick']
                                    # URL文字列を検出して置換
                                    urls = re.findall(r'["\']https?://[^"\']+["\']', onclick)
                                    for found_url in urls:
                                        clean_url = found_url.strip('\'"')
                                        obf_result = obfuscate_url(clean_url)
                                        if isinstance(obf_result, dict):
                                            obf_url = obf_result.get('obfuscated_url')
                                        else:
                                            obf_url = obf_result
                                        if obf_url:
                                            onclick = onclick.replace(found_url, f'"/api/proxy/{obf_url}"')
                                    link['onclick'] = onclick

                                # すべてのdata-*属性を処理
                                for attr_name in list(link.attrs.keys()):
                                    if attr_name.startswith('data-') and isinstance(link[attr_name], str):
                                        attr_value = link[attr_name]
                                        # URLのように見える値だけを処理
                                        if ('://' in attr_value or attr_value.startswith('/')) and not attr_value.startswith('data:'):
                                            try:
                                                normalized_attr_url = urllib.parse.urljoin(final_url, attr_value)
                                                attr_obfuscated = obfuscate_url(normalized_attr_url)
                                                if isinstance(attr_obfuscated, dict):
                                                    attr_obfuscated = attr_obfuscated.get('obfuscated_url')
                                                if attr_obfuscated:
                                                    link[attr_name] = create_proxy_url(attr_obfuscated)
                                                    logger.debug(f"データ属性を処理: {attr_name}={attr_value} → {link[attr_name]}")
                                            except Exception as e:
                                                logger.warning(f"Failed to process data attribute {attr_name}: {str(e)}")
                        except Exception as e:
                            logger.warning(f"Failed to process link {href}: {str(e)}")
                            logger.debug(traceback.format_exc())
                            continue

                # Process all scripts, images, videos, audio, objects, embeds, and other resources
                for tag in soup.find_all(['script', 'img', 'iframe', 'source', 'video', 'audio', 'embed', 'object', 'input', 'track', 'applet', 'frame']):
                    # 処理すべき属性のリスト（タグによって異なる）
                    src_attrs = ['src', 'data', 'poster', 'srcset', 'codebase', 'cite', 'background', 'longdesc', 'usemap']
                    
                    # 各属性をチェックして処理
                    for attr_name in src_attrs:
                        if tag.has_attr(attr_name) and tag[attr_name] and not tag[attr_name].startswith('data:'):
                            attr_value = tag[attr_name]
                            try:
                                # リダイレクト後のURLを使用して相対パスを解決
                                final_url = resp.url
                                # URLの完全な正規化
                                absolute_url = urllib.parse.urljoin(final_url, attr_value)
                                # ログ出力（デバッグ用）
                                logger.debug(f"ソース正規化: {attr_name}={attr_value} → {absolute_url}")

                                # Obfuscate and create proxy URL
                                obfuscated_result = obfuscate_url(absolute_url)
                                if obfuscated_result:
                                    if isinstance(obfuscated_result, dict):
                                        obfuscated = obfuscated_result.get('obfuscated_url')
                                    else:
                                        obfuscated = obfuscated_result

                                    proxy_url = create_proxy_url(obfuscated)
                                    tag[attr_name] = proxy_url
                            except Exception as e:
                                logger.warning(f"Failed to process {attr_name} in {tag.name}: {str(e)}")
                                logger.debug(traceback.format_exc())
                    
                    # srcset属性の特別処理（複数のURL候補を含む）
                    if tag.has_attr('srcset'):
                        try:
                            srcset = tag['srcset']
                            srcset_parts = srcset.split(',')
                            new_srcset_parts = []
                            
                            for part in srcset_parts:
                                part = part.strip()
                                if not part:
                                    continue
                                    
                                # URLと幅/密度指定を分離
                                src_parts = part.split()
                                if len(src_parts) >= 1:
                                    src_url = src_parts[0]
                                    
                                    if not src_url.startswith('data:'):
                                        # URLを正規化して難読化
                                        final_url = resp.url
                                        absolute_url = urllib.parse.urljoin(final_url, src_url)
                                        obfuscated_result = obfuscate_url(absolute_url)
                                        
                                        if obfuscated_result:
                                            if isinstance(obfuscated_result, dict):
                                                obfuscated = obfuscated_result.get('obfuscated_url')
                                            else:
                                                obfuscated = obfuscated_result
                                                
                                            proxy_url = create_proxy_url(obfuscated)
                                            
                                            # 元のサイズ/密度指定を維持
                                            if len(src_parts) > 1:
                                                descriptor = ' '.join(src_parts[1:])
                                                new_srcset_parts.append(f"{proxy_url} {descriptor}")
                                            else:
                                                new_srcset_parts.append(proxy_url)
                            
                            # 処理した結果を元の属性に戻す
                            if new_srcset_parts:
                                tag['srcset'] = ', '.join(new_srcset_parts)
                        except Exception as e:
                            logger.warning(f"Failed to process srcset in {tag.name}: {str(e)}")
                            logger.debug(traceback.format_exc())
                    
                    # すべてのdata-*属性を処理
                    for attr_name in list(tag.attrs.keys()):
                        if attr_name.startswith('data-') and isinstance(tag[attr_name], str):
                            attr_value = tag[attr_name]
                            # URLのように見える値だけを処理
                            if ('://' in attr_value or attr_value.startswith('/')) and not attr_value.startswith('data:'):
                                try:
                                    normalized_attr_url = urllib.parse.urljoin(resp.url, attr_value)
                                    attr_obfuscated = obfuscate_url(normalized_attr_url)
                                    if isinstance(attr_obfuscated, dict):
                                        attr_obfuscated = attr_obfuscated.get('obfuscated_url')
                                    if attr_obfuscated:
                                        tag[attr_name] = create_proxy_url(attr_obfuscated)
                                        logger.debug(f"データ属性を処理: {attr_name}={attr_value} → {tag[attr_name]}")
                                except Exception as e:
                                    logger.warning(f"Failed to process data attribute {attr_name}: {str(e)}")
                    
                    # スクリプトの内容も処理
                    if tag.name == 'script' and tag.string:
                        content = tag.string
                        
                        # Discordでの非推奨unloadイベントリスナーの修正
                        if 'addEventListener("unload"' in content or "addEventListener('unload'" in content:
                            content = content.replace('addEventListener("unload"', 'addEventListener("pagehide"')
                            content = content.replace("addEventListener('unload'", "addEventListener('pagehide'")
                            # その他のバリエーションもカバー
                            content = content.replace("window.addEventListener('unload'", "window.addEventListener('pagehide'")
                            content = content.replace('window.addEventListener("unload"', 'window.addEventListener("pagehide"')
                            content = content.replace('window.onunload', 'window.onpagehide')
                            # ログ出力
                            logger.info("非推奨のunloadイベントをpagehideに置換しました")
                        
                        # URL文字列を検出して置換
                        urls = re.findall(r'["\']https?://[^"\']+["\']', content)
                        for found_url in urls:
                            clean_url = found_url.strip('\'"')
                            obf_result = obfuscate_url(clean_url)
                            if isinstance(obf_result, dict):
                                obf_url = obf_result.get('obfuscated_url')
                            else:
                                obf_url = obf_result
                            if obf_url:
                                content = content.replace(found_url, f'"/api/proxy/{obf_url}"')
                        tag.string = content

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

                            # リダイレクト後のURLを使用して相対パスを解決
                            final_url = resp.url
                            # URLの完全な正規化
                            absolute_url = urllib.parse.urljoin(final_url, original_url)
                            # ログ出力（デバッグ用）
                            logger.debug(f"スタイルURL正規化: {original_url} → {absolute_url}")

                            # Obfuscate and create proxy URL
                            obfuscated_result = obfuscate_url(absolute_url)
                            if obfuscated_result:
                                if isinstance(obfuscated_result, dict):
                                    obfuscated = obfuscated_result.get('obfuscated_url')
                                else:
                                    obfuscated = obfuscated_result

                                proxy_url = create_proxy_url(obfuscated)
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

                                # リダイレクト後のURLを使用して相対パスを解決
                                final_url = resp.url
                                # URLの完全な正規化
                                absolute_url = urllib.parse.urljoin(final_url, original_url)
                                # ログ出力（デバッグ用）
                                logger.debug(f"メタリフレッシュURL正規化: {original_url} → {absolute_url}")

                                # Obfuscate and create proxy URL
                                obfuscated_result = obfuscate_url(absolute_url)
                                if obfuscated_result:
                                    if isinstance(obfuscated_result, dict):
                                        obfuscated = obfuscated_result.get('obfuscated_url')
                                    else:
                                        obfuscated = obfuscated_result

                                    proxy_url = create_proxy_url(obfuscated)
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
            # Handle streaming content and WebSocket upgrades
            if 'upgrade' in request.headers.get('connection', '').lower():
                # Enhanced WebSocket upgrade request
                response = Response(
                    response=resp.raw.read(),
                    status=resp.status_code,
                    direct_passthrough=True
                )
                # Copy all upgrade-related headers
                upgrade_headers = ['connection', 'upgrade', 'sec-websocket-key', 
                                 'sec-websocket-version', 'sec-websocket-protocol',
                                 'sec-websocket-extensions']
                for header in upgrade_headers:
                    if header in request.headers:
                        response.headers[header] = request.headers[header]

                # Add CORS headers for WebSocket
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
            elif any(t in content_type.lower() for t in ['video', 'audio', 'stream', 'octet-stream', 'wasm']) or ('googlevideo.com' in url and 'videoplayback' in url) or url.endswith('.wasm'):
                # Streaming content
                # 特別な処理が必要なコンテンツタイプ
                is_youtube_video = ('googlevideo.com' in url and 'videoplayback' in url)
                is_wasm = 'wasm' in content_type.lower() or url.endswith('.wasm')
                
                # ストリーミングチャンクサイズの最適化
                chunk_size = 8192  # デフォルトサイズ
                if is_youtube_video:
                    chunk_size = 16384  # YouTube動画用の大きいチャンクサイズ
                elif is_wasm or ('discord.com' in url or 'discordapp.com' in url):
                    chunk_size = 32768  # WebAssemblyとDiscordアセット用のもっと大きいチャンクサイズ
                
                response = Response(
                    response=resp.iter_content(chunk_size=chunk_size),
                    status=resp.status_code,
                    direct_passthrough=True
                )
                
                # WebAssemblyのMIMEタイプを正しく設定
                if is_wasm:
                    response.mimetype = 'application/wasm'
                
                # CORSヘッダーの追加（特殊コンテンツタイプ用）
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
                response.headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Range, X-Requested-With, Authorization'
                response.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Content-Type, Accept-Ranges'
                response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
                response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
                
                # レンジリクエスト対応
                if 'content-range' in resp.headers:
                    response.headers['content-range'] = resp.headers['content-range']
                if 'accept-ranges' in resp.headers:
                    response.headers['accept-ranges'] = resp.headers['accept-ranges']
            else:
                # Regular content
                response = Response(
                    response=resp.iter_content(chunk_size=1024),
                    status=resp.status_code
                )

        # Copy headers from the proxied response with enhanced async support
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        for name, value in resp.headers.items():
            if name.lower() not in excluded_headers:
                response.headers[name] = value

        # Add permissive headers for YouTube-like sites and DevTools
        response.headers['Content-Security-Policy'] = (
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
            "script-src * 'unsafe-inline' 'unsafe-eval' data: blob: 'unsafe-hashes' 'wasm-unsafe-eval' https: http:; "
            "style-src * 'unsafe-inline' data:; "
            "img-src * data: blob:; "
            "font-src * data:; "
            "connect-src * data: blob: https: http:; "
            "frame-src *; "
            "media-src * data: blob: https: http:; "
            "worker-src * data: blob:; "
            "trusted-types 'allow-duplicates' * default dompurify google html-sanitizer goog#html jsaction fast-html-policy TrustedTypesPolicy goog#gapi polymer-template polymer-html-literal polymer#imported"
        )

        # Add security headers
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
        response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
        response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Range'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range'
        response.headers['Access-Control-Max-Age'] = '3600'
        response.headers['Service-Worker-Allowed'] = '/'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        # Add headers for frame support
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Frame-Options'] = 'SAMEORIGIN'
        
        # Cache control for dynamic content
        if 'text/html' in content_type or 'application/json' in content_type:
            response.headers['Cache-Control'] = 'no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'

        return response

    except requests.exceptions.Timeout:
        logger.error(f"Request to {url} timed out")
        return jsonify({"error": "Request to target URL timed out", "status": 504}), 504

    except requests.exceptions.RequestException as e:
        logger.error(f"Error proxying request to {url}: {str(e)}")
        return jsonify({"error": f"Error proxying request: {str(e)}", "status": 502}), 502

# ウェイト時間を追加（秒）
DEFAULT_WAIT_TIME = 1  

def create_proxy_url(obfuscated_url):
    return f"/api/{obfuscated_url}"

@proxy_blueprint.route('/<path:obfuscated_url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@rate_limit
def direct_proxy_endpoint(obfuscated_url):
    """
    Direct proxy endpoint that accepts an obfuscated URL and forwards the request
    """
    return proxy_endpoint(obfuscated_url)

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

    # Get expiry hours (default to 1 hour if not provided)
    expiry_hours = data.get('expiry_hours', 1)

    try:
        # Get obfuscated URL with expiry
        obfuscated_result = obfuscate_url(url, expiry_hours)

        # Check if it's a dictionary (new format with expiry info) or just a string
        if isinstance(obfuscated_result, dict):
            obfuscated = obfuscated_result.get('obfuscated_url')
            expiry = obfuscated_result.get('expiry')
        else:
            obfuscated = obfuscated_result
            expiry = None

        proxy_url = create_proxy_url(obfuscated)

        response = {
            "original_url": url,
            "obfuscated_url": obfuscated,
            "proxy_url": proxy_url
        }

        # Add expiry info if available
        if expiry:
            response["expiry"] = expiry

        return jsonify(response)

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
        obfuscated_result = obfuscate_url(url)
        if not obfuscated_result:
            return jsonify({"error": "Failed to process URL", "status": 500}), 500

        # Check if it's a dictionary (new format with expiry info) or just a string
        if isinstance(obfuscated_result, dict):
            obfuscated = obfuscated_result.get('obfuscated_url')
            expiry = obfuscated_result.get('expiry')
        else:
            obfuscated = obfuscated_result
            expiry = None

        proxy_url = create_proxy_url(obfuscated)

        response = {"proxy_url": proxy_url}

        # Add expiry info if available
        if expiry:
            response["expiry"] = expiry

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error in direct_url_endpoint: {str(e)}")
        return jsonify({"error": f"Error processing URL: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({"status": "ok"})

@proxy_blueprint.route('/discord-assets', methods=['GET'])
def discord_assets_endpoint():
    """
    Discord用の特殊アセット取得エンドポイント
    """
    try:
        asset_path = request.args.get('path', '')
        if not asset_path:
            return jsonify({"error": "Asset path is required", "status": 400}), 400
        
        # Discord CDNパスを構築
        discord_cdn_url = f"https://discord.com/assets/{asset_path}"
        
        # ヘッダーセットアップ
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': 'https://discord.com',
            'Referer': 'https://discord.com/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }
        
        # 特別な設定でリクエスト
        return proxy_request(discord_cdn_url, headers=headers, is_resource=True)
    
    except Exception as e:
        logger.error(f"Error in discord_assets_endpoint: {str(e)}")
        return jsonify({"error": f"Asset error: {str(e)}", "status": 500}), 500

# Discord用の追加ルート
@proxy_blueprint.route('/assets/<path:asset_path>', methods=['GET'])
def discord_direct_assets(asset_path):
    """
    Discordの直接アセットにアクセスするためのエンドポイント
    """
    try:
        # もしapi/assets/部分が残っていれば削除
        if asset_path.startswith('api/assets/'):
            asset_path = asset_path.replace('api/assets/', '', 1)
        
        # assets/部分が残っていれば削除
        if asset_path.startswith('assets/'):
            asset_path = asset_path.replace('assets/', '', 1)
            print(f"固有のパスを修正しました: {asset_path}")
            
        # Discordの複数の可能性のあるCDNエンドポイント
        possible_urls = [
            f"https://discord.com/assets/{asset_path}",
            f"https://cdn.discordapp.com/assets/{asset_path}",
            f"https://discordapp.com/assets/{asset_path}",
            f"https://discord.com/{asset_path}"
        ]
        
        # Content-Typeを判断（拡張子ベース）
        content_type = 'application/octet-stream'  # デフォルト
        if asset_path.endswith('.js'):
            content_type = 'application/javascript'
        elif asset_path.endswith('.css'):
            content_type = 'text/css'
        elif asset_path.endswith('.woff2'):
            content_type = 'font/woff2'
        elif asset_path.endswith('.svg'):
            content_type = 'image/svg+xml'
        elif asset_path.endswith('.png'):
            content_type = 'image/png'
        elif asset_path.endswith('.webp'):
            content_type = 'image/webp'
        elif asset_path.endswith('.wasm'):
            content_type = 'application/wasm'
        elif asset_path.endswith('.ico'):
            content_type = 'image/x-icon'
        elif asset_path.endswith('.map'):
            content_type = 'application/json'
        
        # ヘッダーセットアップ
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': 'https://discord.com',
            'Referer': 'https://discord.com/',
            'Sec-Fetch-Dest': 'script',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache'
        }
        
        # すべてのURLを試す
        resp = None
        success_url = None
        
        for url in possible_urls:
            try:
                print(f"Discord CDNを試しています: {url}")
                resp = requests.get(url, headers=headers, stream=True, timeout=15)
                if resp.status_code == 200:
                    print(f"成功: {url}")
                    success_url = url
                    break
            except Exception as url_error:
                print(f"URL {url} でエラー: {str(url_error)}")
                continue
        
        # どのURLも成功しなかった場合
        if resp is None or resp.status_code != 200:
            # JavaScriptファイルの場合は空のJSを返す
            if asset_path.endswith('.js'):
                print(f"JS ファイルが見つからないため空のJSを返します: {asset_path}")
                empty_js = "//Empty JS file\nconsole.log('Asset not found but empty file provided');"
                response = Response(empty_js, mimetype='application/javascript')
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Content-Type'] = 'application/javascript'
                return response
            
            # CSSファイルの場合は空のCSSを返す
            if asset_path.endswith('.css'):
                print(f"CSS ファイルが見つからないため空のCSSを返します: {asset_path}")
                empty_css = "/* Empty CSS file */\n"
                response = Response(empty_css, mimetype='text/css')
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Content-Type'] = 'text/css'
                return response
                
            # マップファイルの場合は空のJSONを返す
            if asset_path.endswith('.map'):
                print(f"Map ファイルが見つからないため空のJSONを返します: {asset_path}")
                empty_map = "{}"
                response = Response(empty_map, mimetype='application/json')
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Content-Type'] = 'application/json'
                return response
                
            # エラーの場合は404を返す
            return jsonify({"error": f"Asset not found: {asset_path}", "status": 404}), 404
            
        # WebAssemblyまたはJavaScriptファイルの場合は特別処理
        if asset_path.endswith('.wasm'):
            response = Response(
                resp.iter_content(chunk_size=32768),
                status=resp.status_code,
                mimetype='application/wasm',
                direct_passthrough=True
            )
            response.headers['Content-Type'] = 'application/wasm'
        else:
            response = Response(
                resp.iter_content(chunk_size=32768),
                status=resp.status_code,
                mimetype=content_type,
                direct_passthrough=True
            )
            response.headers['Content-Type'] = content_type
            
        # CORSヘッダー
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
        response.headers['Cache-Control'] = 'public, max-age=86400'
        
        # その他のヘッダーを転送（必要なものだけ）
        for key, value in resp.headers.items():
            if key.lower() in ['etag', 'last-modified', 'content-disposition']:
                response.headers[key] = value
                
        return response
        
    except Exception as e:
        print(f"Error in discord_direct_assets: {str(e)}")
        
        # エラー時には、重要なアセットタイプには空のコンテンツを返す
        if asset_path.endswith('.js'):
            empty_js = "//Empty JS file\nconsole.log('Asset error but empty file provided');"
            response = Response(empty_js, mimetype='application/javascript')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'application/javascript'
            return response
            
        if asset_path.endswith('.css'):
            empty_css = "/* Empty CSS file */\n"
            response = Response(empty_css, mimetype='text/css')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'text/css'
            return response
            
        if asset_path.endswith('.map'):
            empty_map = "{}"
            response = Response(empty_map, mimetype='application/json')
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'application/json'
            return response
            
        return jsonify({"error": f"Asset error: {str(e)}", "status": 500}), 500

# API WebSocketサポート
@proxy_blueprint.route('/ws/<path:path>', methods=['GET', 'POST', 'OPTIONS'])
def websocket_proxy(path):
    """
    WebSocketプロキシエンドポイント
    """
    if request.method == 'OPTIONS':
        response = Response("")
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Extensions, Upgrade, Connection'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response
    
    try:
        # Discord WebSocket エンドポイント
        if 'gateway.discord.gg' in path or 'remote-auth-gateway.discord.gg' in path:
            if 'gateway.discord.gg' in path:
                ws_url = f"wss://gateway.discord.gg/{path.split('gateway.discord.gg/')[-1]}"
            else:
                ws_url = f"wss://remote-auth-gateway.discord.gg/{path.split('remote-auth-gateway.discord.gg/')[-1]}"
            
            print(f"WebSocketプロキシリクエスト: {ws_url}")
            
            # ヘッダーセットアップ
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
                'Origin': 'https://discord.com',
                'Sec-WebSocket-Version': '13'
            }
            
            # WebSocketリクエストヘッダーの保持
            for header in ['Sec-WebSocket-Key', 'Sec-WebSocket-Extensions', 'Sec-WebSocket-Protocol']:
                if header in request.headers:
                    headers[header] = request.headers[header]
            
            # アップグレードヘッダーの設定
            headers['Connection'] = 'Upgrade'
            headers['Upgrade'] = 'websocket'
            
            # WebSocketリクエストの転送
            response = Response("", status=101)
            response.headers['Connection'] = 'Upgrade'
            response.headers['Upgrade'] = 'websocket'
            response.headers['Sec-WebSocket-Accept'] = request.headers.get('Sec-WebSocket-Key', '')
            if 'Sec-WebSocket-Protocol' in request.headers:
                response.headers['Sec-WebSocket-Protocol'] = request.headers['Sec-WebSocket-Protocol']
            
            return response
        else:
            return jsonify({"error": "Unsupported WebSocket endpoint", "status": 400}), 400
    
    except Exception as e:
        print(f"WebSocketプロキシエラー: {str(e)}")
        return jsonify({"error": f"WebSocket error: {str(e)}", "status": 500}), 500

@proxy_blueprint.route('/wasm-fix', methods=['OPTIONS', 'GET'])
def wasm_fix_endpoint():
    """
    WebAssembly MIME型修正エンドポイント
    """
    if request.method == 'OPTIONS':
        response = Response("")
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Range, X-Requested-With, Authorization'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response
    
    try:
        wasm_url = request.args.get('url', '')
        if not wasm_url:
            return jsonify({"error": "WASM URL is required", "status": 400}), 400
        
        # ヘッダーセットアップ
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        # WebAssembly専用処理でリクエスト
        resp = requests.get(wasm_url, headers=headers, stream=True, timeout=30)
        response = Response(resp.iter_content(chunk_size=32768), mimetype='application/wasm')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Content-Type'] = 'application/wasm'
        return response
    
    except Exception as e:
        logger.error(f"Error in wasm_fix_endpoint: {str(e)}")
        return jsonify({"error": f"WASM error: {str(e)}", "status": 500}), 500