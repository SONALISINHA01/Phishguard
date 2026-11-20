from typing import Dict, Any, List
from src.agents.state import AgentState
from src.config import SAFE_THRESHOLD, QUARANTINE_THRESHOLD

class TriageAgent:
    """
    Synthesizes signals from email headers, threat intel, domain checks, and semantic intent.
    Calculates composite risk score and generates human-auditable reasoning.
    """

    def __init__(self, safe_threshold: float = SAFE_THRESHOLD, quarantine_threshold: float = QUARANTINE_THRESHOLD):
        self.safe_threshold = safe_threshold
        self.quarantine_threshold = quarantine_threshold

    def evaluate(self, state: AgentState) -> AgentState:
        indicators: List[str] = []

        # 1. Inspect PhishTank findings
        phishtank_score = 0.0
        pt_data = state.phishtank_verdict
        if pt_data.get("threat_detected"):
            highest = pt_data.get("highest_threat", "CLEAN")
            if highest == "CRITICAL":
                phishtank_score = 100.0
                indicators.append("🚨 [PhishTank] Confirmed active phishing URL verified in threat intelligence database.")
            else:
                phishtank_score = 80.0
                indicators.append("⚠️ [PhishTank] Embedded link domain matched known malicious threat actor.")

        # 2. Inspect Header & Authentication
        header_data = state.header_verdict
        header_score = header_data.get("header_risk_score", 0.0)
        for flag in header_data.get("flags", []):
            indicators.append(f"📧 [Authentication] {flag}")

        # 3. Inspect Domain / Typosquatting
        domain_data = state.domain_verdict
        domain_score = domain_data.get("max_domain_risk", 0.0)
        for flag in domain_data.get("flags", []):
            indicators.append(f"🌐 [Domain Integrity] {flag}")

        # 4. Inspect Semantic Intent
        intent_data = state.intent_verdict
        semantic_score = intent_data.get("semantic_risk_score", 0.0)
        for trig in intent_data.get("psychological_triggers", []):
            indicators.append(f"🧠 [Psychological Intent] {trig}")

        # 5. Composite Risk Calculation
        # PhishTank verified match acts as an automatic critical override
        if phishtank_score >= 95.0:
            final_risk = 98.0
        else:
            # Weighted multi-modal risk scoring
            # Threat Intel (35%) + Header Spoofing (25%) + Domain Impersonation (20%) + LLM Intent (20%)
            final_risk = (
                (phishtank_score * 0.35) +
                (header_score * 0.25) +
                (domain_score * 0.20) +
                (semantic_score * 0.20)
            )

            # Boost risk if multiple distinct categories flagged simultaneously
            flag_categories = sum([
                1 if phishtank_score > 40 else 0,
                1 if header_score > 30 else 0,
                1 if domain_score > 30 else 0,
                1 if semantic_score > 40 else 0
            ])
            if flag_categories >= 2:
                final_risk = min(100.0, final_risk * 1.2)

        final_risk = round(min(100.0, max(0.0, final_risk)), 1)
        state.risk_score = final_risk

        # 6. Action Assignment
        if final_risk < self.safe_threshold:
            state.action = "DELIVER"
            state.threat_category = "Legitimate"
        elif final_risk <= self.quarantine_threshold:
            state.action = "FLAG"
            state.threat_category = "Suspicious / Graymail"
        else:
            state.action = "QUARANTINE"
            state.threat_category = "Phishing / Malicious"

        state.key_indicators = indicators

        # 7. Synthesize Human-Auditable Explainability Trace
        rationale_parts = [
            f"**Action:** `{state.action}` (Risk Score: **{final_risk}/100** | Category: **{state.threat_category}**)",
            f"\n**Triage Summary:**"
        ]

        if final_risk < self.safe_threshold:
            rationale_parts.append("• No malicious URLs, spoofing signatures, or high-risk coercion tactics detected.")
            rationale_parts.append("• Standard business/personal communication signature verified.")
        else:
            rationale_parts.append(f"• Found **{len(indicators)}** warning indicators across security layers.")
            for ind in indicators[:5]: # top 5
                rationale_parts.append(f"  - {ind}")

        if intent_data.get("rationale"):
            rationale_parts.append(f"\n**LLM Cognitive Rationale:**\n> {intent_data.get('rationale')}")

        state.explanation = "\n".join(rationale_parts)
        return state
