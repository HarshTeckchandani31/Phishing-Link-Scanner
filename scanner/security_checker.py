import re
from urllib.parse import urlparse
from datetime import datetime

class SecurityChecker:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'bank', 'verify',
            'secure', 'update', 'password', 'credential'
        ]

    def analyze_url(self, url):
        """
        Performs various security checks on the given URL.
        Returns a dictionary containing analysis results.
        """
        results = {
            'suspicious_keywords': self._check_suspicious_keywords(url),
            'protocol_check': self._check_protocol(url),
            'domain_analysis': self._analyze_domain(url),
            'suspicious_patterns': self._check_suspicious_patterns(url)
        }
        return results

    def _check_suspicious_keywords(self, url):
        """Check for suspicious keywords in the URL."""
        url_lower = url.lower()
        found_keywords = [word for word in self.suspicious_keywords 
                         if word in url_lower]
        return found_keywords

    def _check_protocol(self, url):
        """Check if the URL uses HTTPS."""
        parsed_url = urlparse(url)
        return {
            'secure': parsed_url.scheme == 'https',
            'protocol': parsed_url.scheme
        }

    def _analyze_domain(self, url):
        """Analyze domain characteristics."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        return {
            'domain': domain,
            'subdomain_count': len(domain.split('.')) - 2,
            'length': len(domain),
            'contains_suspicious_tld': self._check_suspicious_tld(domain)
        }

    def _check_suspicious_tld(self, domain):
        """Check for suspicious top-level domains."""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        return any(domain.endswith(tld) for tld in suspicious_tlds)

    def _check_suspicious_patterns(self, url):
        """Check for suspicious URL patterns."""
        patterns = {
            'unusual_chars': r'[<>{}|\^~\[\]`]',
            'multiple_subdomains': r'([a-z0-9]+\.){3,}[a-z0-9]+\.[a-z]+',
            'numeric_domain': r'://[0-9.-]+/',
            'long_url': len(url) > 100,
            'hexadecimal': r'%[0-9a-fA-F]{2}',
            'excessive_dots': r'\.{2,}',
            'excessive_hyphens': r'-{2,}'
        }
        
        results = {}
        for pattern_name, pattern in patterns.items():
            if pattern_name == 'long_url':
                results[pattern_name] = pattern
            else:
                results[pattern_name] = bool(re.search(pattern, url))
                
        return results