import base64
import hashlib
import urllib.parse
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Simple encryption key - in production, use a proper secret key from environment variables
ENCRYPTION_KEY = "proxyapi_secure_key"

def is_valid_url(url):
    """
    Check if a URL is valid
    """
    try:
        result = urllib.parse.urlparse(url)
        # Check for scheme and netloc
        return all([result.scheme, result.netloc])
    except Exception as e:
        logger.error(f"Error validating URL: {str(e)}")
        return False

def xor_encrypt(data, key):
    """
    Simple XOR encryption for URL obfuscation
    """
    key_bytes = key.encode('utf-8')
    # Ensure data is in bytes format
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    key_len = len(key_bytes)
    
    # XOR each byte with the corresponding byte from the key
    encrypted = bytearray()
    for i, byte in enumerate(data_bytes):
        key_byte = key_bytes[i % key_len]
        encrypted.append(byte ^ key_byte)
    
    return encrypted

def xor_decrypt(data, key):
    """
    Simple XOR decryption (same as encryption)
    """
    # XOR is symmetric, so encryption and decryption are the same
    # But we need to ensure data is bytes, not str
    if isinstance(data, str):
        data = data.encode('utf-8')
    return xor_encrypt(data, key)

def obfuscate_url(url, expiry_hours=1):
    """
    Obfuscate a URL using a combination of XOR encryption and base64 encoding
    
    Args:
        url (str): The URL to obfuscate
        expiry_hours (int, optional): Number of hours before the URL expires. Defaults to 1.
        
    Returns:
        dict: Dictionary containing the obfuscated URL and expiry information
    """
    try:
        # Normalize the URL
        url = urllib.parse.unquote(url)
        
        # Get current timestamp
        current_time = datetime.now()
        
        # Add a timestamp to prevent replay attacks
        timestamped_url = f"{url}|{current_time.timestamp()}"
        
        # Encrypt the URL
        encrypted = xor_encrypt(timestamped_url, ENCRYPTION_KEY)
        
        # Base64 encode the encrypted data
        encoded = base64.urlsafe_b64encode(encrypted).decode('utf-8')
        
        # Add a simple checksum
        checksum = hashlib.md5(encoded.encode('utf-8')).hexdigest()[:8]
        obfuscated = f"{encoded}.{checksum}"
        
        # Calculate expiry time
        expiry_time = current_time.replace(microsecond=0)
        expiry_timestamp = (expiry_time.timestamp() + (expiry_hours * 3600))
        expiry_str = datetime.fromtimestamp(expiry_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Return as dictionary with additional info
        return {
            "status": "success",
            "obfuscated_url": obfuscated,
            "original_url": url,
            "expiry": expiry_str
        }
    
    except Exception as e:
        logger.error(f"Error obfuscating URL: {str(e)}")
        return None

def deobfuscate_url(obfuscated, expiry_check=True):
    """
    Deobfuscate a URL by reversing the obfuscation process
    URLs expire after 1 hour by default
    
    Args:
        obfuscated (str): The obfuscated URL to decode
        expiry_check (bool, optional): Whether to check URL expiry. Defaults to True.
        
    Returns:
        str or None: The original URL if valid, None if invalid or expired
    """
    try:
        # Check format and extract parts
        parts = obfuscated.split('.')
        if len(parts) != 2:
            logger.warning("Invalid obfuscated URL format")
            return None
        
        encoded, checksum = parts
        
        # Verify checksum
        calculated_checksum = hashlib.md5(encoded.encode('utf-8')).hexdigest()[:8]
        if calculated_checksum != checksum:
            logger.warning("Checksum verification failed")
            return None
        
        # Base64 decode
        try:
            encrypted = base64.urlsafe_b64decode(encoded)
        except Exception as e:
            logger.error(f"Base64 decoding error: {str(e)}")
            return None
        
        # Decrypt
        decrypted = xor_encrypt(encrypted, ENCRYPTION_KEY).decode('utf-8')
        
        # Extract timestamp and URL
        parts = decrypted.split('|')
        if len(parts) != 2:
            logger.warning("Invalid decrypted URL format (missing timestamp)")
            return None
            
        url = parts[0]
        try:
            timestamp = float(parts[1])
            
            # Check if URL has expired (default 1 hour = 3600 seconds)
            if expiry_check:
                current_time = datetime.now().timestamp()
                if current_time - timestamp > 3600:
                    logger.warning("URL has expired (older than 1 hour)")
                    return None
        except Exception as e:
            logger.error(f"Error parsing timestamp: {str(e)}")
            return None
        
        return url
    
    except Exception as e:
        logger.error(f"Error deobfuscating URL: {str(e)}")
        return None
