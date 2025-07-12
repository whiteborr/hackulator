# app/tools/encoders.py
import base64
import codecs
import re
import binascii

def detect_and_decode(text):
    """Auto-detect and decode common encodings"""
    results = []
    
    # Base64 detection and decoding
    if is_base64(text):
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            results.append(('Base64', decoded))
        except:
            pass
    
    # ROT13 detection and decoding
    if contains_rot13_pattern(text):
        try:
            decoded = codecs.decode(text, 'rot_13')
            results.append(('ROT13', decoded))
        except:
            pass
    
    # Hex detection and decoding
    if is_hex(text):
        try:
            decoded = bytes.fromhex(text).decode('utf-8')
            results.append(('Hex', decoded))
        except:
            pass
    
    # URL encoding detection
    if '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text):
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            results.append(('URL Encoded', decoded))
        except:
            pass
    
    return results

def is_base64(text):
    """Check if text looks like Base64"""
    if not text or len(text) % 4 != 0:
        return False
    
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    return bool(base64_pattern.match(text)) and len(text) > 4

def contains_rot13_pattern(text):
    """Check if text might be ROT13 encoded"""
    # Simple heuristic: check for common ROT13 patterns
    rot13_indicators = ['nqzva', 'frpher', 'cnffjbeq', 'ybtvа']
    return any(indicator in text.lower() for indicator in rot13_indicators)

def is_hex(text):
    """Check if text is hexadecimal"""
    if len(text) % 2 != 0:
        return False
    
    try:
        int(text, 16)
        return len(text) > 4 and all(c in '0123456789ABCDEFabcdef' for c in text)
    except ValueError:
        return False

def decode_javascript_obfuscation(js_content):
    """Basic JavaScript deobfuscation patterns"""
    results = []
    
    # Detect eval(function(p,a,c,k,e,d) pattern
    eval_pattern = r'eval\(function\(p,a,c,k,e,d\).*?\}\((.*?)\)\)'
    matches = re.findall(eval_pattern, js_content, re.DOTALL)
    
    for match in matches:
        results.append(('JS Obfuscated', f"Found obfuscated code: {match[:100]}..."))
    
    # Look for encoded strings
    string_patterns = [
        r'"([A-Za-z0-9+/]{20,}={0,2})"',  # Base64 strings
        r"'([A-Za-z0-9+/]{20,}={0,2})'"   # Base64 strings
    ]
    
    for pattern in string_patterns:
        matches = re.findall(pattern, js_content)
        for match in matches:
            if is_base64(match):
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    results.append(('JS Base64', decoded))
                except:
                    pass
    
    return results