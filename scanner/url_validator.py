import re
from urllib.parse import urlparse

def validate_url(url):
    """
    Validates URL format and checks for common suspicious patterns.
    Returns True if URL appears valid, False otherwise.
    """
    try:
        # Check basic URL format
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
            
        # Check for valid scheme (http or https)
        if result.scheme not in ['http', 'https']:
            return False
            
        # Check for IP address URLs (potentially suspicious)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, result.netloc):
            return False
            
        return True
    except:
        return False