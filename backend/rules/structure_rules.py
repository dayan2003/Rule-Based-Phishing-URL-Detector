from config import RULE_WEIGHTS
from core.url_parser import URLParser

def check_structure_rules(parser: URLParser):
    triggered = []
    
    domain = parser.domain
    path = parser.path
    original_url = parser.original_url
    
    # Rule 1: Long URL
    if len(original_url) > 75:
        triggered.append({
            "name": "Long URL detected",
            "score": RULE_WEIGHTS["LONG_URL"],
            "description": "The URL is unusually long (>75 chars), often used to hide the true destination."
        })
        
    # Rule 2: Excessive Subdomains
    # Count dots in domain. www.google.com -> 2 dots. 
    # login.update.secure.bank.com -> 4 dots.
    if domain.count('.') > 3:
        triggered.append({
            "name": "Excessive Subdomains",
            "score": RULE_WEIGHTS["EXCESSIVE_SUBDOMAINS"],
            "description": "Multiple subdomains detected. Phishers often use this to obscure the actual domain."
        })
        
    # Rule 3: @ Symbol in URL
    # Browsers interpret everything before @ as username.
    # http://google.com@phishing.com -> goes to phishing.com
    if '@' in original_url:
        triggered.append({
            "name": "At Symbol (@) Detected",
            "score": RULE_WEIGHTS["MULTIPLE_AT_SYMBOLS"], # Reusing weight or defined new
            "description": "The '@' symbol can be used to redirect users to a malicious site while showing a legitimate one."
        })
    
    # Rule 4: Hyphens in domain (typosquatting hint)
    # Legit domains use hyphens, but many (example-secure-login) is suspicious
    hyphen_count = domain.split('.')[0].count('-')
    if hyphen_count >= 2:
        triggered.append({
            "name": "Multiple Hyphens in Domain",
            "score": RULE_WEIGHTS["HYPHENS_IN_DOMAIN"],
            "description": "Multiple hyphens in the domain name can indicate an attempt to mimic a legitimate brand."
        })
        
    # Rule 5: HTTPS in Path (Deception)
    # e.g. http://example.com/https/login or http://example.com/ssl/verify
    if "https" in path.lower() or "ssl" in path.lower():
        triggered.append({
            "name": "HTTPS/SSL in Path",
            "score": RULE_WEIGHTS["HTTPS_IN_PATH_NOT_PROTOCOL"],
            "description": "The terms 'https' or 'ssl' appear in the path, often used to trick users into believing the site is secure."
        })
        
    # Rule 6: Suspicious Keywords in Path
    from utils.constants import SUSPICIOUS_KEYWORDS
    found_path_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path.lower() and kw not in domain]
    if found_path_keywords:
        triggered.append({
            "name": "Suspicious Keyword in Path",
            "score": RULE_WEIGHTS["SUSPICIOUS_KEYWORD_IN_PATH"],
            "description": f"URL path contains suspicious keywords: {', '.join(found_path_keywords)}"
        })

    return triggered
