from urllib.parse import urlparse
import ipaddress
import re

class URLParser:
    def __init__(self, url: str):
        self.original_url = url
        self.parsed = None
        self.domain = ""
        self.path = ""
        self.query = ""
        self.protocol = ""
        
        self._parse()

    def _parse(self):
        """
        Decomposes the URL into its components.
        Handles missing scheme by defaulting to http:// for parsing purposes if needed,
        though input should ideally be validated first.
        """
        to_parse = self.original_url
        if not to_parse.startswith(('http://', 'https://')):
            to_parse = 'http://' + to_parse
        
        self.parsed = urlparse(to_parse)
        self.protocol = self.parsed.scheme
        self.domain = self.parsed.netloc
        self.path = self.parsed.path
        self.query = self.parsed.query

    def get_domain(self):
        return self.domain

    def get_components(self):
        return {
            "protocol": self.protocol,
            "domain": self.domain,
            "path": self.path,
            "query": self.query,
            "original": self.original_url
        }

    def is_ip_address(self):
        """Checks if the domain is an IP address."""
        # Remove port if present
        domain_only = self.domain.split(':')[0]
        # Remove brackets if ipv6
        domain_only = domain_only.strip("[]")
        
        try:
            ipaddress.ip_address(domain_only)
            return True
        except ValueError:
            return False
