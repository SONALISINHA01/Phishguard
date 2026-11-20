import json
import re
import urllib.request
from typing import Dict, Any
from src.config import GEMINI_API_KEY

class IntentAgent:
    """
    Analyzes email intent and psychological persuasion tactics (urgency, coercion, credential requests).
    Uses Gemini API when available, otherwise falls back to local heuristic rules.
    """

    def __init__(self, api_key: str = GEMINI_API_KEY):
        self.api_key = api_key

    def analyze(self, subject: str, body: str, sender: str) -> Dict[str, Any]:
        """
        Runs LLM semantic intent analysis.
        Uses Gemini API if key is present; falls back to heuristic intent analyzer otherwise.
        """
        if self.api_key and self.api_key.strip() != "your_gemini_api_key_here":
            try:
                return self._call_gemini_api(subject, body, sender)
            except Exception as e:
                print(f"[IntentAgent] Gemini API fallback due to: {e}")
                return self._heuristic_analysis(subject, body, sender, fallback_reason=str(e))
        else:
            return self._heuristic_analysis(subject, body, sender, fallback_reason="No GEMINI_API_KEY configured; used local semantic analyzer.")

    def _call_gemini_api(self, subject: str, body: str, sender: str) -> Dict[str, Any]:
        """Direct REST call to Google Gemini 1.5/2.5 Flash API for low latency and zero external SDK friction."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"

        system_instruction = (
            "You are an expert cybersecurity forensic analyst specializing in phishing, spear-phishing, "
            "and business email compromise (BEC). Analyze the provided email for social engineering indicators, "
            "psychological levers (urgency, fear, greed, authority), and credential-harvesting intents. "
            "Output strictly valid JSON with this exact schema:\n"
            "{\n"
            '  "psychological_triggers": ["string"],\n'
            '  "intent_type": "string",\n'
            '  "urgency_score": float (0-100),\n'
            '  "deceit_score": float (0-100),\n'
            '  "semantic_risk_score": float (0-100),\n'
            '  "rationale": "string"\n'
            "}"
        )

        user_content = f"From: {sender}\nSubject: {subject}\n\nBody:\n{body}"

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_instruction}\n\nEmail Content:\n{user_content}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
            candidate = result["candidates"][0]["content"]["parts"][0]["text"]
            data = json.loads(candidate)
            data["analysis_engine"] = "Gemini 1.5 Flash (API)"
            return data

    def _heuristic_analysis(self, subject: str, body: str, sender: str, fallback_reason: str = "") -> Dict[str, Any]:
        """
        Rule-based NLP and pattern matching fallback.
        Provides robust offline testing and immediate demo capability.
        """
        text = f"{subject} {body}".lower()
        triggers = []
        urgency_score = 0.0
        deceit_score = 0.0

        # 1. Urgency / Panic patterns
        urgency_patterns = [
            r"immediately", r"within 24 hours", r"urgent", r"account will be suspended",
            r"action required", r"limited time", r"final warning", r"unauthorized access",
            r"security alert", r"suspended immediately"
        ]
        for pat in urgency_patterns:
            if re.search(pat, text):
                triggers.append(f"Urgency trigger: '{pat}'")
                urgency_score += 25.0

        # 2. Credential harvesting / CTA patterns
        cta_patterns = [
            r"click here to verify", r"verify your account", r"update your password",
            r"confirm your identity", r"login to restore", r"reactivate your",
            r"review transaction", r"wire transfer", r"gift card"
        ]
        for pat in cta_patterns:
            if re.search(pat, text):
                triggers.append(f"Deceptive Call-To-Action: '{pat}'")
                deceit_score += 30.0

        # 3. Authority / Security impersonation
        authority_patterns = [
            r"it helpdesk", r"security team", r"fraud department", r"account administrator",
            r"paypal support", r"microsoft office 365 team"
        ]
        for pat in authority_patterns:
            if re.search(pat, text):
                triggers.append(f"Authority impersonation claim: '{pat}'")
                deceit_score += 25.0

        urgency_score = min(100.0, urgency_score)
        deceit_score = min(100.0, deceit_score)
        semantic_risk = min(100.0, (urgency_score * 0.45) + (deceit_score * 0.55))

        intent_type = "Legitimate"
        if semantic_risk >= 70.0:
            intent_type = "Credential Harvesting / Urgent Coercion"
        elif semantic_risk >= 35.0:
            intent_type = "Suspicious Marketing / Social Engineering"

        rationale = (
            f"Detected {len(triggers)} social engineering cues. "
            f"Urgency rating: {urgency_score:.1f}/100, Deceptive Intent: {deceit_score:.1f}/100."
        )
        if triggers:
            rationale += f" Notable indicators: {', '.join(triggers[:3])}."

        return {
            "psychological_triggers": triggers,
            "intent_type": intent_type,
            "urgency_score": urgency_score,
            "deceit_score": deceit_score,
            "semantic_risk_score": semantic_risk,
            "rationale": rationale,
            "analysis_engine": "Semantic Heuristic Engine (Offline / Fallback)",
            "engine_note": fallback_reason
        }
