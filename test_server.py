#!/usr/bin/env python3
"""
Unit tests for LNURL-pay server
Run with: python -m pytest test_server.py -v
or: python test_server.py
"""

import unittest
import json
import sys
import os

# Add parent directory to path to import server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import functions from server (before config is loaded)
import re
from unittest.mock import patch, MagicMock

class TestSanitization(unittest.TestCase):
    """Test input sanitization functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Patch the server module's global variables
        import server
        server.USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
        server.ALLOWED_USERNAMES = []
        server.REQUIRE_VALID_USERNAME = False
        server.COMMENT_BLACKLIST = [
            r'https?://',
            r'www\.',
            r'@.*\.',
        ]
    
    def test_sanitize_username_valid(self):
        """Test valid usernames"""
        from server import sanitize_username
        
        valid_usernames = ['alice', 'bob123', 'user_name', 'user-name', 'user.name', 'A', 'a1']
        for username in valid_usernames:
            with self.subTest(username=username):
                result = sanitize_username(username)
                self.assertEqual(result, username)
    
    def test_sanitize_username_invalid(self):
        """Test invalid usernames"""
        from server import sanitize_username
        
        invalid_usernames = [
            '',              # Empty
            ' ',             # Whitespace only
            'user name',     # Spaces
            'user@domain',   # @ symbol
            'user#123',      # # symbol
            '<script>',      # HTML
            'a' * 101,       # Too long
        ]
        for username in invalid_usernames:
            with self.subTest(username=username):
                result = sanitize_username(username)
                self.assertIsNone(result)
    
    def test_sanitize_username_whitespace_trim(self):
        """Test username whitespace trimming"""
        from server import sanitize_username
        
        self.assertEqual(sanitize_username('  alice  '), 'alice')
        self.assertEqual(sanitize_username('\talice\n'), 'alice')
    
    def test_sanitize_username_whitelist(self):
        """Test username whitelist enforcement"""
        import server
        from server import sanitize_username
        
        server.ALLOWED_USERNAMES = ['alice', 'bob']
        server.REQUIRE_VALID_USERNAME = True
        
        # Allowed usernames
        self.assertEqual(sanitize_username('alice'), 'alice')
        self.assertEqual(sanitize_username('Alice'), 'Alice')  # Case insensitive
        self.assertEqual(sanitize_username('BOB'), 'BOB')
        
        # Not allowed
        self.assertIsNone(sanitize_username('charlie'))
        self.assertIsNone(sanitize_username('eve'))
    
    def test_sanitize_comment_valid(self):
        """Test valid comments"""
        from server import sanitize_comment
        
        valid_comments = [
            'Thanks for the coffee!',
            'Payment for services',
            '',
            'Test 123',
        ]
        for comment in valid_comments:
            with self.subTest(comment=comment):
                result = sanitize_comment(comment)
                self.assertEqual(result, comment.strip())
    
    def test_sanitize_comment_invalid(self):
        """Test comments with prohibited content"""
        from server import sanitize_comment
        
        invalid_comments = [
            'Check out https://spam.com',
            'Visit www.spam.com',
            'Email me at spam@example.com',
            'http://evil.site',
        ]
        for comment in invalid_comments:
            with self.subTest(comment=comment):
                result = sanitize_comment(comment)
                self.assertIsNone(result)
    
    def test_sanitize_comment_whitespace_trim(self):
        """Test comment whitespace trimming"""
        from server import sanitize_comment
        
        self.assertEqual(sanitize_comment('  test  '), 'test')
        self.assertEqual(sanitize_comment('\n\ttest\n'), 'test')

class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""
    
    def test_validate_config_valid(self):
        """Test valid configuration"""
        from server import validate_config
        
        # Create a temporary macaroon file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test_macaroon_data')
            macaroon_path = f.name
        
        try:
            valid_config = {
                "server": {"host": "127.0.0.1", "port": 5001},
                "lnd": {
                    "onion_address": "test.onion",
                    "port": 8080,
                    "macaroon_path": macaroon_path
                },
                "tor": {"proxy": "socks5h://127.0.0.1:9050"},
                "lnurlp": {
                    "domain": "example.com",
                    "min_sendable": 1000,
                    "max_sendable": 100000,
                    "comment_allowed": 200
                }
            }
            
            errors = validate_config(valid_config)
            self.assertEqual(errors, [])
        finally:
            os.unlink(macaroon_path)
    
    def test_validate_config_invalid_port(self):
        """Test invalid port numbers"""
        from server import validate_config
        
        invalid_configs = [
            {"server": {"port": 0}},
            {"server": {"port": 65536}},
            {"server": {"port": "5001"}},
            {"lnd": {"port": -1}},
        ]
        
        for config in invalid_configs:
            with self.subTest(config=config):
                errors = validate_config(config)
                self.assertTrue(len(errors) > 0)
    
    def test_validate_config_amount_range(self):
        """Test min/max sendable validation"""
        from server import validate_config
        
        # Min > Max
        config = {
            "server": {"port": 5001},
            "lnd": {"port": 8080, "onion_address": "test.onion", "macaroon_path": "/tmp/fake"},
            "lnurlp": {
                "domain": "test.com",
                "min_sendable": 100000,
                "max_sendable": 1000,
                "comment_allowed": 200
            }
        }
        
        errors = validate_config(config)
        self.assertTrue(any('min_sendable' in err and 'max_sendable' in err for err in errors))

class TestStatistics(unittest.TestCase):
    """Test statistics tracking"""
    
    def test_increment_stat(self):
        """Test thread-safe stat incrementing"""
        from server import increment_stat, stats
        
        # Reset stats
        stats['test_counter'] = 0
        
        increment_stat('test_counter')
        self.assertEqual(stats['test_counter'], 1)
        
        increment_stat('test_counter')
        self.assertEqual(stats['test_counter'], 2)

def run_tests():
    """Run all tests"""
    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests())
