import sys
import os

# Add backend directory to sys.path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.url_parser import URLParser
from core.verdict import VerdictSystem
from rules.domain_rules import check_domain_rules
from rules.structure_rules import check_structure_rules
from config import RISK_THRESHOLDS

# Test Data
GOOD_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://openai.com",
    "https://www.wikipedia.org",
    "https://support.google.com/accounts",
    "https://docs.microsoft.com/en-us/learn",
    "https://developer.apple.com/documentation",
    "https://platform.openai.com/docs",
    "https://www.amazon.com/gp/product/B09V3KXJPB/ref=ppx_yo_dt_b_asin_title_o00_s00",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
]

SUSPICIOUS_URLS = [
    "https://secure-login-help.com",
    "https://account-verification-center.net",
    "https://update-your-password.org",
    "https://my-secure-cloud-storage.info",
    "https://fast-login-support.online",
    "https://randomsite.xyz",
    "https://tech-update.info"
]

PHISHING_URLS = [
    "chat-gpt-ai-pc.info",
    "openai-login-support.xyz",
    "google-secure-account-verification.info",
    "paypal-account-check.net",
    "microsoft-password-reset-help.com",
    "facebook-security-warning.info",
    "amazon-update-payment-method.xyz",
    "http://192.168.1.10/login",
    "http://45.67.89.123/secure",
    "http://login.example.com/https/secure",
    "http://verify-user.com/ssl/login",
    "http://google.com@phishingsite.net",
    "http://paypal.com@login-update.info",
    "support-openai-ai.com",
    "chatgpt-ai-support-center.info",
    "helpdesk-google-ai.net",
    "secure-chat-gpt-login-update.info",
    "account-verify-openai-support.xyz"
]

def test_url(url, expected_verdict_type):
    print(f"Testing: {url}")
    try:
        parser = URLParser(url)
        domain_rules = check_domain_rules(parser)
        structure_rules = check_structure_rules(parser)
        
        all_rules = domain_rules + structure_rules
        total_score = sum(rule['score'] for rule in all_rules)
        
        verdict_system = VerdictSystem()
        verdict = verdict_system.get_verdict(total_score)
        
        # Check against expectation
        passed = False
        if expected_verdict_type == "GOOD":
            if verdict == "Legitimate":
                passed = True
        elif expected_verdict_type == "SUSPICIOUS":
            if verdict == "Suspicious":
                passed = True
        elif expected_verdict_type == "PHISHING":
            if verdict == "Phishing":
                passed = True

        if passed:
            # print("  Result: [PASS]")
            return True
        else:
            print(f"Testing: {url}")
            print(f"  Score: {total_score}")
            print(f"  Verdict: {verdict}")
            print(f"  Triggered Rules: {[r['name'] for r in all_rules]}")
            print(f"  Result: [FAIL] (Expected {expected_verdict_type}, got {verdict})")
            return False

    except Exception as e:
        print(f"  Error processing URL: {e}")
        return False

def run_tests():
    print("=== STARTING BASELINE TESTS ===")
    
    passed_count = 0
    total_count = 0
    
    print("\n--- GOOD URLs (Expected: Legitimate) ---")
    for url in GOOD_URLS:
        total_count += 1
        if test_url(url, "GOOD"):
            passed_count += 1
            
    print("\n--- SUSPICIOUS URLs (Expected: Suspicious) ---")
    for url in SUSPICIOUS_URLS:
        total_count += 1
        if test_url(url, "SUSPICIOUS"):
            passed_count += 1
            
    print("\n--- PHISHING URLs (Expected: Phishing) ---")
    for url in PHISHING_URLS:
        total_count += 1
        if test_url(url, "PHISHING"):
            passed_count += 1
            
    print(f"\nTotal Passed: {passed_count}/{total_count}")
    
if __name__ == "__main__":
    run_tests()
