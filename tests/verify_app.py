import sys
import os
import json
import unittest

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from app import app

class TestPhishingDetector(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_safe_url(self):
        response = self.app.post('/analyze', 
                                 data=json.dumps({'url': 'https://www.google.com'}),
                                 content_type='application/json')
        data = json.loads(response.data)
        print(f"\nTesting SAFE URL (google.com): {data['verdict']} (Score: {data['score']})")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['verdict'], 'SAFE')
        self.assertEqual(data['score'], 0)

    def test_phishing_ip_url(self):
        # IP address should trigger high risk
        response = self.app.post('/analyze', 
                                 data=json.dumps({'url': 'http://192.168.1.1/login'}),
                                 content_type='application/json')
        data = json.loads(response.data)
        print(f"Testing IP URL: {data['verdict']} (Score: {data['score']})")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['verdict'], 'PHISHING')
        self.assertGreaterEqual(data['score'], 75)
        
    def test_suspicious_keywords(self):
        # 'secure-login.com' -> might be suspicious depending on rules. 
        # based on my implementation, 'secure' is a keyword. 'login' is a keyword. 
        # domain_rules: checks for keywords in domain.
        response = self.app.post('/analyze', 
                                 data=json.dumps({'url': 'http://secure-login-update.com'}),
                                 content_type='application/json')
        data = json.loads(response.data)
        print(f"Testing Suspicious URL: {data['verdict']} (Score: {data['score']})")
        # Should be at least suspicious or have some score
        self.assertGreater(data['score'], 0)

    def test_invalid_url(self):
        response = self.app.post('/analyze', 
                                 data=json.dumps({'url': 'not_a_url'}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
