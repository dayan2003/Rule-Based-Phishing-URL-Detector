from config import RISK_THRESHOLDS

class VerdictSystem:
    def get_verdict(self, score: int) -> str:
        if score >= RISK_THRESHOLDS["HIGH"]:
            return "Phishing"
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            return "Suspicious"
        else:
            return "Legitimate"
