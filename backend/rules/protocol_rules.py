from config import RULE_WEIGHTS
from core.url_parser import URLParser
from utils.constants import SUSPICIOUS_KEYWORDS

def check_protocol_rules(parser: URLParser):
    triggered = []
    protocol = parser.protocol
    path = parser.path.lower()
    
    # Rule 1: HTTPS in path but not protocol
    # e.g. http://login.com/https-secure
    if "https" in path and protocol != "https":
        triggered.append({
            "name": "Deceptive HTTPS in Path",
            "score": RULE_WEIGHTS["HTTPS_IN_PATH_NOT_PROTOCOL"],
            "description": "The URL path contains 'https', mimicking a secure connection, but the actual protocol is not HTTPS."
        })
        
    # Rule 2: Suspicious keywords in path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path]
    if found_keywords:
        triggered.append({
            "name": "Suspicious Keywords in Path",
            "score": RULE_WEIGHTS["SUSPICIOUS_KEYWORD_IN_PATH"],
            "description": f"The URL path contains sensitive keywords ({', '.join(found_keywords)}) often used to trick users."
        })

    return triggered
