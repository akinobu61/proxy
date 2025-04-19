import base64
import hashlib
import time
import urllib.parse
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import re

# 簡単な暗号化キー - 実際の使用では環境変数から取得する安全なキーを使用してください
ENCRYPTION_KEY = "proxyapi_secure_key"

def is_valid_url(url):
    """
    URLが有効かどうかをチェック
    """
    try:
        result = urllib.parse.urlparse(url)
        # スキームとネットロックをチェック
        return all([result.scheme, result.netloc])
    except Exception as e:
        print(f"URLの検証エラー: {str(e)}")
        return False

def xor_encrypt(data, key):
    """
    URLの難読化のための単純なXOR暗号化
    """
    key_bytes = key.encode('utf-8')
    # データがバイト形式であることを確認
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    key_len = len(key_bytes)
    
    # 各バイトをキーの対応するバイトでXOR
    encrypted = bytearray()
    for i, byte in enumerate(data_bytes):
        key_byte = key_bytes[i % key_len]
        encrypted.append(byte ^ key_byte)
    
    return encrypted

def xor_decrypt(data, key):
    """
    単純なXOR復号化（暗号化と同じ）
    """
    # XORは対称的なので、暗号化と復号化は同じ
    # ただし、データがバイトであり、文字列でないことを確認する必要があります
    if isinstance(data, str):
        data = data.encode('utf-8')
    return xor_encrypt(data, key)

def obfuscate_url(url):
    """
    XOR暗号化とbase64エンコーディングを組み合わせてURLを難読化
    URL有効期限: 1時間
    """
    try:
        # URLを正規化
        url = urllib.parse.unquote(url)
        
        # リプレイ攻撃を防ぐためにタイムスタンプを追加
        timestamped_url = f"{url}|{datetime.now().timestamp()}"
        
        # URLを暗号化
        encrypted = xor_encrypt(timestamped_url, ENCRYPTION_KEY)
        
        # 暗号化されたデータをBase64エンコード
        encoded = base64.urlsafe_b64encode(encrypted).decode('utf-8')
        
        # 単純なチェックサムを追加
        checksum = hashlib.md5(encoded.encode('utf-8')).hexdigest()[:8]
        obfuscated = f"{encoded}.{checksum}"
        
        return obfuscated
    
    except Exception as e:
        print(f"URL難読化エラー: {str(e)}")
        return None

def deobfuscate_url(obfuscated):
    """
    難読化プロセスを逆にしてURLを復号化
    URLは1時間後に期限切れ
    """
    try:
        # 形式をチェックして部品を抽出
        parts = obfuscated.split('.')
        if len(parts) != 2:
            print("無効な難読化URL形式")
            return None
        
        encoded, checksum = parts
        
        # チェックサムを検証
        calculated_checksum = hashlib.md5(encoded.encode('utf-8')).hexdigest()[:8]
        if calculated_checksum != checksum:
            print("チェックサム検証失敗")
            return None
        
        # Base64デコード
        try:
            encrypted = base64.urlsafe_b64decode(encoded)
        except Exception as e:
            print(f"Base64デコードエラー: {str(e)}")
            return None
        
        # 復号化
        decrypted = xor_encrypt(encrypted, ENCRYPTION_KEY).decode('utf-8')
        
        # タイムスタンプとURLを抽出
        parts = decrypted.split('|')
        if len(parts) != 2:
            print("無効な復号化URL形式（タイムスタンプがない）")
            return None
            
        url = parts[0]
        try:
            timestamp = float(parts[1])
            # URLが期限切れかどうかチェック（1時間 = 3600秒）
            current_time = datetime.now().timestamp()
            if current_time - timestamp > 3600:
                print("URLの期限切れ（1時間以上前）")
                return None
        except Exception as e:
            print(f"タイムスタンプの解析エラー: {str(e)}")
            return None
        
        return url
    
    except Exception as e:
        print(f"URL復号化エラー: {str(e)}")
        return None

def proxy_request(url, wait_time=1):
    """
    指定されたURLにリクエストを転送し、レスポンスを返す
    wait_time: リクエスト前に待機する秒数（デフォルト: 1秒）
    """
    if not is_valid_url(url):
        return {"error": "無効なターゲットURL", "status": 400}
    
    try:
        print(f"{url}へのリクエストを{wait_time}秒の遅延でプロキシ")
        
        # 指定された時間だけ待機
        if wait_time > 0:
            time.sleep(wait_time)
        
        # リクエストをターゲットURLに転送
        resp = requests.get(
            url=url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            timeout=10,
            allow_redirects=True  # 自動的にリダイレクトを処理
        )
        
        return {
            "status": resp.status_code,
            "content_type": resp.headers.get('content-type', ''),
            "content": resp.text,
            "headers": dict(resp.headers),
            "url": resp.url  # リダイレクト後のURL
        }
    
    except requests.exceptions.Timeout:
        return {"error": "ターゲットURLへのリクエストがタイムアウト", "status": 504}
    
    except requests.exceptions.RequestException as e:
        return {"error": f"リクエストのプロキシエラー: {str(e)}", "status": 502}

def process_html_content(html_content, base_url):
    """
    HTML内のURLをプロキシURLに変換
    """
    try:
        # BeautifulSoupを使用してHTMLを解析
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # すべてのリンクを処理
        for link in soup.find_all(['a', 'link']):
            href = link.get('href')
            if href:
                # フラグメントのみのリンクをスキップ（例：#section）
                if href.startswith('#'):
                    continue
                    
                # 相対URLを処理
                if href.startswith('/'):
                    absolute_url = f"{base_url}{href}"
                # 絶対URLを処理
                elif href.startswith(('http://', 'https://')):
                    absolute_url = href
                # プロトコル相対URL（//example.com）を処理
                elif href.startswith('//'):
                    parsed_url = urllib.parse.urlparse(base_url)
                    absolute_url = f"{parsed_url.scheme}:{href}"
                else:
                    # mailto:, tel:, javascript: リンクをスキップ
                    if any(href.startswith(scheme) for scheme in ['mailto:', 'tel:', 'javascript:']):
                        continue
                    # その他の相対パス（/で始まらない）
                    parsed_url = urllib.parse.urlparse(base_url)
                    path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                    absolute_url = f"{base_url}{path_base}/{href}"
                
                # 難読化して新しいプロキシURLを作成
                obfuscated = obfuscate_url(absolute_url)
                if obfuscated:
                    link['href'] = f"proxy:/{obfuscated}"
        
        # スクリプト、画像、その他のリソースを処理
        for tag in soup.find_all(['script', 'img', 'iframe', 'source']):
            src = tag.get('src')
            if src and not src.startswith('data:'):  # data: URLをスキップ
                # 相対URLを処理
                if src.startswith('/'):
                    absolute_url = f"{base_url}{src}"
                # 絶対URLを処理
                elif src.startswith(('http://', 'https://')):
                    absolute_url = src
                # プロトコル相対URL（//example.com）を処理
                elif src.startswith('//'):
                    parsed_url = urllib.parse.urlparse(base_url)
                    absolute_url = f"{parsed_url.scheme}:{src}"
                else:
                    # その他の相対パス（/で始まらない）
                    parsed_url = urllib.parse.urlparse(base_url)
                    path_base = '/'.join(parsed_url.path.split('/')[:-1]) if '/' in parsed_url.path else ''
                    absolute_url = f"{base_url}{path_base}/{src}"
                
                # 難読化して新しいプロキシURLを作成
                obfuscated = obfuscate_url(absolute_url)
                if obfuscated:
                    tag['src'] = f"proxy:/{obfuscated}"
        
        # 文字列に戻す
        return str(soup)
    
    except Exception as e:
        print(f"HTML処理エラー: {str(e)}")
        return html_content

# Google Colab用のメソッド - HTML出力のサンプル
def display_processed_html(url, wait_time=1):
    """
    URLを取得し、処理されたHTMLを表示
    """
    from IPython.display import HTML, display
    
    response = proxy_request(url, wait_time)
    
    if 'error' in response:
        return f"エラー: {response['error']} (ステータス: {response['status']})"
    
    content_type = response.get('content_type', '')
    
    if 'text/html' in content_type:
        # 基本URLを取得して相対URLを解決
        parsed_url = urllib.parse.urlparse(response.get('url', url))
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # HTMLを処理
        processed_html = process_html_content(response['content'], base_url)
        
        # 処理されたHTMLを表示
        display(HTML(f"<h2>処理済みHTML - {url}</h2>"))
        display(HTML(f"<pre>{processed_html[:500]}...</pre>"))
        
        return {
            "status": response['status'],
            "content_type": content_type,
            "url": response.get('url', url),
            "processed_html_length": len(processed_html)
        }
    else:
        return {
            "status": response['status'],
            "content_type": content_type,
            "url": response.get('url', url),
            "message": "HTMLではないコンテンツ"
        }

# サンプル使用方法
def demo():
    # URL難読化のデモ
    url = "https://example.com"
    
    print(f"元のURL: {url}")
    
    # URLを難読化
    obfuscated = obfuscate_url(url)
    print(f"難読化されたURL: {obfuscated}")
    
    # 難読化されたURLを復号化
    deobfuscated = deobfuscate_url(obfuscated)
    print(f"復号化されたURL: {deobfuscated}")
    
    # プロキシリクエストのデモ
    response = proxy_request(url, wait_time=0)  # wait_time=0で即時処理
    
    if 'error' in response:
        print(f"エラー: {response['error']} (ステータス: {response['status']})")
    else:
        print(f"ステータス: {response['status']}")
        print(f"コンテンツタイプ: {response['content_type']}")
        print(f"コンテンツ（最初の100文字）: {response['content'][:100]}...")

if __name__ == "__main__":
    demo()