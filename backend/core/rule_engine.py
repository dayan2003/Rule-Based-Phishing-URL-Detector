from rules.structure_rules import check_structure_rules
from rules.domain_rules import check_domain_rules
from rules.protocol_rules import check_protocol_rules
from .url_parser import URLParser

class RuleEngine:
    def __init__(self):
        # Allow expanding with more rules easily
        self.rule_modules = [
            check_structure_rules,
            check_domain_rules,
            check_protocol_rules
        ]

    def run_rules(self, parser: URLParser):
        """
        Runs all registered rules against the parsed URL.
        """
        all_triggered = []
        
        for rule_func in self.rule_modules:
            try:
                results = rule_func(parser)
                if results:
                    all_triggered.extend(results)
            except Exception as e:
                # Log error but don't crash detection
                print(f"Error executing rule {rule_func.__name__}: {e}")
                
        return all_triggered
