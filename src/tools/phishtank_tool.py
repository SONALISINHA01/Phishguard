import csv
import os
import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from src.config import PHISHTANK_CSV, PHISHTANK_DIR

class PhishTankTool:
    """
    PhishTank Threat Intelligence Tool.
    Queries the PhishTank verified online phishing dataset to identify known malicious URLs.
    """
    def __init__(self, csv_path: str = PHISHTANK_CSV):
        self.csv_path = csv_path
        self.verified_urls = set()
        self.verified_domains = set()
        self._load_or_initialize_dataset()

    def _load_or_initialize_dataset(self):
        """Loads verified phishing URLs from PhishTank CSV or creates starter seed data."""
        if not os.path.exists(self.csv_path):
            self._create_seed_phishtank_data()

        try:
            with open(self.csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = (row.get("url") or "").strip().lower()
                    if url:
                        self.verified_urls.add(url)
                        domain = self._extract_domain(url)
                        if domain:
                            self.verified_domains.add(domain)
        except Exception as e:
            print(f"[PhishTankTool] Error loading CSV: {e}")

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL, stripping protocol and path."""
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    def _create_seed_phishtank_data(self):
        """Creates sample verified PhishTank data for immediate testing."""
        os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)
        seed_samples = [
            {"phish_id": "800101", "url": "http://paypal-security-account-verification.com/login", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800101", "submission_time": "2026-11-01T12:00:00+00:00", "verified": "yes", "verification_time": "2026-11-01T12:30:00+00:00", "online": "yes", "target": "PayPal"},
            {"phish_id": "800102", "url": "http://netflix-billing-update-required.net/signin", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800102", "submission_time": "2026-11-02T10:00:00+00:00", "verified": "yes", "verification_time": "2026-11-02T10:15:00+00:00", "online": "yes", "target": "Netflix"},
            {"phish_id": "800103", "url": "https://microsoft-office365-pass-reset.org/auth", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800103", "submission_time": "2026-11-03T09:00:00+00:00", "verified": "yes", "verification_time": "2026-11-03T09:20:00+00:00", "online": "yes", "target": "Microsoft"},
            {"phish_id": "800104", "url": "http://chase-security-portal.secure-banking.top/verify", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800104", "submission_time": "2026-11-04T15:00:00+00:00", "verified": "yes", "verification_time": "2026-11-04T15:45:00+00:00", "online": "yes", "target": "Chase Bank"},
            {"phish_id": "800105", "url": "http://apple-icloud-findmy-disabled.xyz/unlock", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800105", "submission_time": "2026-11-05T18:00:00+00:00", "verified": "yes", "verification_time": "2026-11-05T18:10:00+00:00", "online": "yes", "target": "Apple"},
            {"phish_id": "800106", "url": "http://secure-login-docusign.com-view.info/document", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800106", "submission_time": "2026-11-06T08:00:00+00:00", "verified": "yes", "verification_time": "2026-11-06T08:15:00+00:00", "online": "yes", "target": "DocuSign"},
            {"phish_id": "800107", "url": "http://amazon-unusual-activity-alert.co/resolve", "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=800107", "submission_time": "2026-11-07T14:30:00+00:00", "verified": "yes", "verification_time": "2026-11-07T14:45:00+00:00", "online": "yes", "target": "Amazon"}
        ]
        fieldnames = ["phish_id", "url", "phish_detail_url", "submission_time", "verified", "verification_time", "online", "target"]
        with open(self.csv_path, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(seed_samples)

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scans an individual URL against PhishTank verified records.
        """
        clean_url = url.strip().lower()
        domain = self._extract_domain(clean_url)

        # Check exact URL match
        if clean_url in self.verified_urls:
            return {
                "url": url,
                "is_match": True,
                "threat_level": "CRITICAL",
                "matched_by": "exact_url",
                "details": f"Exact URL confirmed in PhishTank database."
            }

        # Check domain match
        if domain and domain in self.verified_domains:
            return {
                "url": url,
                "is_match": True,
                "threat_level": "HIGH",
                "matched_by": "domain_match",
                "details": f"Domain '{domain}' is associated with verified phishing attacks in PhishTank."
            }

        return {
            "url": url,
            "is_match": False,
            "threat_level": "CLEAN",
            "matched_by": "none",
            "details": "No direct match in PhishTank ground-truth database."
        }

    def scan_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Scans a list of URLs and aggregates threat findings."""
        findings = []
        has_phish = False
        highest_threat = "CLEAN"

        for u in urls:
            res = self.scan_url(u)
            findings.append(res)
            if res["is_match"]:
                has_phish = True
                if res["threat_level"] == "CRITICAL":
                    highest_threat = "CRITICAL"
                elif highest_threat != "CRITICAL":
                    highest_threat = "HIGH"

        return {
            "total_urls_scanned": len(urls),
            "threat_detected": has_phish,
            "highest_threat": highest_threat,
            "url_findings": findings
        }
