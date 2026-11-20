import re
from urllib.parse import urlparse
from typing import List, Dict, Any
from src.config import TARGETED_BRANDS

class DomainTool:
    """
    Domain and URL Typosquatting / Lookalike Analyzer.
    Detects brand impersonation, deceptive homoglyphs, and abnormal domain structures.
    """

    HIGH_RISK_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".buzz", ".tk", ".ml", ".cf", ".gq"}

    def __init__(self, targeted_brands: List[str] = None):
        self.targeted_brands = targeted_brands or TARGETED_BRANDS

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyzes a single domain for spoofing and deceptive characteristics."""
        flags = []
        domain_risk = 0.0
        clean_domain = domain.lower().strip()

        # Check for IP address used as domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_domain):
            flags.append(f"Direct IP address used as host: '{clean_domain}' (common phishing evasion technique)")
            domain_risk += 50.0

        # Check high-risk TLD
        for tld in self.HIGH_RISK_TLDS:
            if clean_domain.endswith(tld):
                flags.append(f"High-risk, abuse-prone Top Level Domain: '{tld}'")
                domain_risk += 25.0
                break

        # Check excessive subdomains
        parts = clean_domain.split(".")
        if len(parts) > 4:
            flags.append(f"Excessive subdomain depth ({len(parts)} parts): '{clean_domain}'")
            domain_risk += 20.0

        # Brand typosquatting and deceptive hyphenation checks
        for brand in self.targeted_brands:
            # Check if brand is embedded in domain with hyphens or prefixes
            # e.g., 'paypal-security-login.com' or 'verify-apple-id.net'
            if brand in clean_domain and not clean_domain.endswith(f"{brand}.com") and not clean_domain.endswith(f".{brand}.com"):
                flags.append(f"Brand impersonation: Domain '{clean_domain}' contains brand keyword '{brand}' but is not an official domain.")
                domain_risk += 45.0
                break

            # Lookalike / Levenshtein distance check
            for part in parts[:-1]: # exclude TLD
                # Normalize common visual leet-speak substitutions
                normalized_part = part.replace("0", "o").replace("1", "l").replace("vv", "w")
                dist = self._levenshtein_distance(brand, normalized_part)
                if dist == 1 and len(brand) >= 4:
                    flags.append(f"Typosquatting detected: '{part}' is a 1-character lookalike to brand '{brand}'")
                    domain_risk += 40.0
                    break

        domain_risk = min(100.0, domain_risk)
        return {
            "domain": clean_domain,
            "risk_score": domain_risk,
            "flags": flags,
            "is_suspicious": domain_risk >= 30.0
        }

    def analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyzes all extracted URLs from an email."""
        domain_results = []
        overall_flags = []
        max_risk = 0.0

        for url in urls:
            try:
                if not url.startswith(("http://", "https://")):
                    url = "http://" + url
                parsed = urlparse(url)
                domain = parsed.hostname or ""
                if domain:
                    res = self.analyze_domain(domain)
                    res["url"] = url
                    domain_results.append(res)
                    overall_flags.extend(res["flags"])
                    if res["risk_score"] > max_risk:
                        max_risk = res["risk_score"]
            except Exception:
                continue

        return {
            "max_domain_risk": max_risk,
            "flags": list(set(overall_flags)),
            "analyzed_domains": domain_results
        }

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Computes minimum edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
