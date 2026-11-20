import re
from typing import Dict, Any

class HeaderAuthTool:
    """
    Email Header and Protocol Authentication Analyzer.
    Evaluates SPF, DKIM, DMARC statuses and flags sender spoofing / display-name deception.
    """

    def analyze_headers(self, headers: Dict[str, str], sender: str, return_path: str = "") -> Dict[str, Any]:
        flags = []
        risk_score = 0.0

        # 1. Parse From Address and Display Name
        display_name, email_address = self._parse_from(sender)
        sender_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""

        # 2. Display Name Spoofing Check
        # e.g. Display name says "PayPal Support" but sender domain is "gmail.com" or "security-alerts.xyz"
        spoof_check = self._check_display_name_spoof(display_name, sender_domain)
        if spoof_check["is_spoofed"]:
            flags.append(spoof_check["reason"])
            risk_score += spoof_check["risk_penalty"]

        # 3. Return-Path vs From Divergence
        if return_path:
            _, return_email = self._parse_from(return_path)
            return_domain = return_email.split("@")[-1].lower() if "@" in return_email else ""
            if return_domain and sender_domain and return_domain != sender_domain:
                flags.append(f"Header divergence: Return-Path domain '{return_domain}' does not match From domain '{sender_domain}'")
                risk_score += 25.0

        # 4. Check SPF, DKIM, DMARC from Authentication-Results / Received-SPF
        auth_results = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
        received_spf = headers.get("Received-SPF", "") or headers.get("received-spf", "")

        spf_status = self._extract_auth_status(auth_results, received_spf, "spf")
        dkim_status = self._extract_auth_status(auth_results, "", "dkim")
        dmarc_status = self._extract_auth_status(auth_results, "", "dmarc")

        if spf_status == "fail":
            flags.append("SPF validation failed (Sender IP not authorized)")
            risk_score += 35.0
        elif spf_status == "softfail":
            flags.append("SPF softfail (Sender IP questionable)")
            risk_score += 20.0

        if dkim_status == "fail":
            flags.append("DKIM cryptographic signature verification failed")
            risk_score += 30.0

        if dmarc_status == "fail":
            flags.append("DMARC alignment policy failed")
            risk_score += 35.0

        # Cap header risk score to 100
        risk_score = min(100.0, risk_score)

        return {
            "display_name": display_name,
            "sender_domain": sender_domain,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "header_risk_score": risk_score,
            "flags": flags,
            "is_suspicious": risk_score >= 30.0
        }

    def _parse_from(self, sender_raw: str):
        """Extracts display name and email address from raw From line."""
        match = re.match(r'^(?:"?([^"]*)"?\s)?(?:<?(.+@[^>]+)>?)$', sender_raw.strip())
        if match:
            name = (match.group(1) or "").strip()
            email = (match.group(2) or "").strip()
            return name, email
        return "", sender_raw.strip()

    def _check_display_name_spoof(self, display_name: str, sender_domain: str) -> Dict[str, Any]:
        """Detects if trusted brand name appears in display name but not in the sender domain."""
        if not display_name:
            return {"is_spoofed": False, "reason": "", "risk_penalty": 0.0}

        brand_keywords = [
            "paypal", "apple", "microsoft", "google", "amazon", "netflix",
            "chase", "wells fargo", "bank of america", "docusign", "security team", "it helpdesk"
        ]

        name_lower = display_name.lower()
        for brand in brand_keywords:
            clean_brand = brand.replace(" ", "")
            if brand in name_lower:
                # If the brand is claimed in the name, does domain match?
                if clean_brand not in sender_domain and not sender_domain.endswith(f"{clean_brand}.com"):
                    return {
                        "is_spoofed": True,
                        "reason": f"Display Name Spoofing detected: Claims to be '{display_name}' but sent from unrelated domain '{sender_domain}'",
                        "risk_penalty": 45.0
                    }

        return {"is_spoofed": False, "reason": "", "risk_penalty": 0.0}

    def _extract_auth_status(self, auth_header: str, spf_header: str, proto: str) -> str:
        """Extracts pass/fail/softfail/none status for a protocol."""
        combined = f"{auth_header} {spf_header}".lower()
        if not combined.strip():
            return "none"

        pattern = rf"{proto}=([a-zA-Z]+)"
        match = re.search(pattern, combined)
        if match:
            return match.group(1).lower()

        if f"{proto} pass" in combined:
            return "pass"
        if f"{proto} fail" in combined:
            return "fail"
        return "none"
