import unittest
from scanner.url_validator import validate_url

class TestURLValidator(unittest.TestCase):
    def test_valid_urls(self):
        valid_urls = [
            'https://example.com',
            'https://sub.example.com',
            'http://example.com/path',
            'https://example.com/path?param=value'
        ]
        for url in valid_urls:
            self.assertTrue(validate_url(url))
    
    def test_invalid_urls(self):
        invalid_urls = [
            'not_a_url',
            'ftp://example.com',
            'https://',
            'https://192.168.1.1',
            'http://.com',
            'https://example.'
        ]
        for url in invalid_urls:
            self.assertFalse(validate_url(url))