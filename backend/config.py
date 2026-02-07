# Risk Scoring Thresholds
# If score >= HIGH -> PHISHING
# If score >= MEDIUM -> SUSPICIOUS
# Else -> SAFE
RISK_THRESHOLDS = {
    "HIGH": 70,
    "MEDIUM": 30
}


# Rule Weights (Points added to risk score)
RULE_WEIGHTS = {
    # High Risk
    "IP_ADDRESS_FOUND": 80,
    "PUNYCODE_DETECTED": 70,
    "SUSPICIOUS_KEYWORD_IN_DOMAIN": 25,
    "MISLEADING_URL_SHORTENER": 50, # If we detect common shorteners (optional check)
    
    # Medium Risk
    "HTTPS_IN_PATH_NOT_PROTOCOL": 45,
    "MULTIPLE_AT_SYMBOLS": 40,
    "EXCESSIVE_SUBDOMAINS": 30,
    
    # Low Risk
    "LONG_URL": 15,
    "SUSPICIOUS_KEYWORD_IN_PATH": 20,
    "HIGH_ENTROPY_DOMAIN": 15, # Random characters
    "UNCOMMON_TLD": 30,
    "HYPHENS_IN_DOMAIN": 10
}

POPULAR_BRANDS = [
    "chatgpt", "openai", "google", "paypal",
    "microsoft", "apple", "amazon", "facebook"
]
