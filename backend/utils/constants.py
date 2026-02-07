# Known legitimate domains to avoid false positives (common ones)
LEGITIMATE_DOMAINS = {
    "google.com", "www.google.com",
    "facebook.com", "www.facebook.com",
    "amazon.com", "www.amazon.com",
    "apple.com", "www.apple.com",
    "microsoft.com", "www.microsoft.com",
    "github.com", "www.github.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "openai.com", "www.openai.com",
    "wikipedia.org", "www.wikipedia.org",
    "youtube.com", "www.youtube.com"
}

# Suspicious keywords that often appear in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "secure", "account", "login", "verify", "update", "bank", "signin",
    "confirm", "wallet", "crypto", "unlock", "bonus", "free", "gift"
]

# Sensitive brands often targeted
TARGETED_BRANDS = [
    "paypal", "netflix", "apple", "microsoft", "facebook", "whatsapp",
    "amazon", "google", "instagram", "chase", "wellsfargo", "irs",
    "openai", "chatgpt"
]
