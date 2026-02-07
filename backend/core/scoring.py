class Scorer:
    def __init__(self):
        pass

    def calculate_total_score(self, triggered_rules: list) -> int:
        """
        Sums the scores of all triggered rules.
        """
        total_score = 0
        for rule in triggered_rules:
            total_score += rule.get('score', 0)
        return total_score
