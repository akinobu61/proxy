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
    data_bytes = data.encode('utf-8')
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
    return xor_encrypt(data, key)

def obfuscate_url(url):
    """
    Obfuscate a URL using a combination of XOR encryption and base64 encoding
    """
    try:
        # Normalize the URL
        url = urllib.parse.unquote(url)
        
        # Add a timestamp to prevent replay attacks
        timestamped_url = f"{url}|{datetime.now().timestamp()}"
        
        # Encrypt the URL
        encrypted = xor_encrypt(timestamped_url, ENCRYPTION_KEY)
        
        # Base64 encode the encrypted data
        encoded = base64.urlsafe_b64encode(encrypted).decode('utf-8')
        
        # Add a simple checksum
        checksum = hashlib.md5(encoded.encode('utf-8')).hexdigest()[:8]
        obfuscated = f"{encoded}.{checksum}"
        
        return obfuscated
    
    except Exception as e:
        logger.error(f"Error obfuscating URL: {str(e)}")
        return None

def deobfuscate_url(obfuscated):
    """
    Deobfuscate a URL by reversing the obfuscation process
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
        
        # Remove timestamp
        url = decrypted.split('|')[0]
        
        return url
    
    except Exception as e:
        logger.error(f"Error deobfuscating URL: {str(e)}")
        return None
