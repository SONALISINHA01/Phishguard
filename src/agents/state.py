from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

@dataclass
class AgentState:
    """
    State object passed between specialized agents in the PhishGuard pipeline.
    """
    # Raw email inputs
    email_id: str
    sender: str
    subject: str
    body_text: str
    raw_headers: Dict[str, str] = field(default_factory=dict)
    extracted_urls: List[str] = field(default_factory=list)

    # Sub-agent outputs
    header_verdict: Dict[str, Any] = field(default_factory=dict)
    domain_verdict: Dict[str, Any] = field(default_factory=dict)
    phishtank_verdict: Dict[str, Any] = field(default_factory=dict)
    intent_verdict: Dict[str, Any] = field(default_factory=dict)

    # Triage synthesis outputs
    risk_score: float = 0.0          # 0.0 to 100.0
    action: str = "PENDING"          # DELIVER, FLAG, QUARANTINE
    threat_category: str = "UNKNOWN" # Legitimate, Phishing, BEC, Suspicious
    explanation: str = ""            # Chain-of-thought rationale for analysts
    key_indicators: List[str] = field(default_factory=list)

    # Human-in-the-Loop tracking
    is_overridden: bool = False
    human_override_action: Optional[str] = None # e.g. "RELEASE_TO_INBOX", "CONFIRM_PHISHING"
    reviewer_notes: Optional[str] = None
    reviewed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email_id": self.email_id,
            "sender": self.sender,
            "subject": self.subject,
            "body_text": self.body_text,
            "extracted_urls": self.extracted_urls,
            "header_verdict": self.header_verdict,
            "domain_verdict": self.domain_verdict,
            "phishtank_verdict": self.phishtank_verdict,
            "intent_verdict": self.intent_verdict,
            "risk_score": self.risk_score,
            "action": self.action,
            "threat_category": self.threat_category,
            "explanation": self.explanation,
            "key_indicators": self.key_indicators,
            "is_overridden": self.is_overridden,
            "human_override_action": self.human_override_action,
            "reviewer_notes": self.reviewer_notes,
            "reviewed_at": self.reviewed_at
        }
