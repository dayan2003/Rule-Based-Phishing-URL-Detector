import re
from config import RULE_WEIGHTS
from utils.constants import (
    SUSPICIOUS_KEYWORDS,
    LEGITIMATE_DOMAINS,
    TARGETED_BRANDS
)
from core.url_parser import URLParser


def check_domain_rules(parser: URLParser):
    triggered = []
    domain = parser.get_domain()
    
    # Rule 1: IP Address
    if parser.is_ip_address():
        triggered.append({
            "name": "IP Address as Hostname",
            "score": RULE_WEIGHTS["IP_ADDRESS_FOUND"],
            "description": "The URL uses an IP address instead of a domain name. This is rare for legitimate sites."
        })
        
    # Rule 2: Punycode (xn--)
    if 'xn--' in domain:
        triggered.append({
            "name": "Punycode Detected",
            "score": RULE_WEIGHTS["PUNYCODE_DETECTED"],
            "description": "Punycode defined characters found. This might be a homograph attack (e.g., using Cyrillic letters to look like Latin)."
        })
        
    # Rule 3: Suspicious Keywords in Domain
    # e.g., "apple-secure-login.com" -> contains "secure", "login"
    # We shouldn't flag if the domain IS the keyword exactly (unlikely for keywords) but combined.
    # Or if it mimics a brand.
    
    # Rule 3: Suspicious Keywords in Domain
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain]
    
    # Check if legitimate (whitelisted)
    # A domain is legit if it implies a known legitimate domain is the suffix
    # e.g. "support.google.com" ends with "google.com" -> Legit
    is_legit = False
    for legit in LEGITIMATE_DOMAINS:
        if domain == legit or domain.endswith("." + legit):
            is_legit = True
            break
            
    if found_keywords and not is_legit:
        triggered.append({
            "name": "Suspicious Keyword in Domain",
            "score": RULE_WEIGHTS["SUSPICIOUS_KEYWORD_IN_DOMAIN"],
            "description": f"Domain contains suspicious security-related keywords: {', '.join(found_keywords)}"
        })
            
    # Rule: Brand Impersonation with Hyphens
    # Only run if not whitelisted
    if not is_legit:
        for brand in TARGETED_BRANDS:
            # Check if brand is in domain (ignoring hyphens for obfuscation)
            # But be careful not to flag the brand itself if it wasn't whitelisted for some reason
            # e.g. "openai-support.com" -> contains "openai"
            clean_domain = domain.replace("-", "")
            
            if brand in clean_domain:
                 # Ensure we don't flag "openai.com" as impersonating "openai" if it wasn't in LEGITIMATE_DOMAINS
                 # The 'is_legit' check above handles known ones, but as a fallback:
                 if domain == f"{brand}.com" or domain.endswith(f".{brand}.com"):
                     continue
                     
                 triggered.append({
                    "name": "Brand Impersonation Detected",
                    "score": 70,
                    "description": f"The domain appears to impersonate the brand '{brand}'."
                })
                 break

    # Rule: Uncommon / High-risk TLD
    if domain.endswith((".info", ".xyz", ".top", ".tk", ".ml")):
        triggered.append({
            "name": "Uncommon or High-Risk TLD",
            "score": RULE_WEIGHTS["UNCOMMON_TLD"],
            "description": "The domain uses a TLD commonly associated with phishing sites."
        })

    return triggered
