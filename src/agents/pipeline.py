import re
import uuid
from typing import Dict, Any, List, Optional
from src.agents.state import AgentState
from src.tools.phishtank_tool import PhishTankTool
from src.tools.header_auth_tool import HeaderAuthTool
from src.tools.domain_tool import DomainTool
from src.agents.intent_agent import IntentAgent
from src.agents.triage_agent import TriageAgent

class PhishGuardPipeline:
    """
    Coordinates email analysis across authentication, domain, threat intel, and intent modules.
    """

    def __init__(self, gemini_api_key: str = ""):
        self.phishtank_tool = PhishTankTool()
        self.header_tool = HeaderAuthTool()
        self.domain_tool = DomainTool()
        self.intent_agent = IntentAgent(api_key=gemini_api_key)
        self.triage_agent = TriageAgent()

    def extract_urls(self, text: str) -> List[str]:
        """Extract all HTTP/HTTPS links and bare domains from email body and text."""
        url_pattern = r'https?://[^\s<>"\')]+|www\.[^\s<>"\')]+'
        matches = re.findall(url_pattern, text)
        clean_urls = []
        for m in matches:
            cleaned = m.rstrip(".,;!?:")
            if cleaned not in clean_urls:
                clean_urls.append(cleaned)
        return clean_urls

    def process_email(
        self,
        sender: str,
        subject: str,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        email_id: Optional[str] = None
    ) -> AgentState:
        """
        Executes end-to-end multi-agent evaluation pipeline on a single email.
        """
        headers = headers or {}
        email_id = email_id or str(uuid.uuid4())[:8]
        extracted_urls = self.extract_urls(body)

        # Initialize State
        state = AgentState(
            email_id=email_id,
            sender=sender,
            subject=subject,
            body_text=body,
            raw_headers=headers,
            extracted_urls=extracted_urls
        )

        # 1. Parallel / Sequential Tool Evaluations
        # A. Header & Authentication Inspection
        return_path = headers.get("Return-Path", "") or headers.get("return-path", "")
        state.header_verdict = self.header_tool.analyze_headers(
            headers=headers,
            sender=sender,
            return_path=return_path
        )

        # B. URL & Threat Intel (PhishTank lookup)
        state.phishtank_verdict = self.phishtank_tool.scan_urls(extracted_urls)

        # C. Domain & Typosquatting Analysis
        state.domain_verdict = self.domain_tool.analyze_urls(extracted_urls)

        # D. LLM Psychological & Social Engineering Intent Analysis
        state.intent_verdict = self.intent_agent.analyze(
            subject=subject,
            body=body,
            sender=sender
        )

        # 2. Synthesis & Triage Decision
        state = self.triage_agent.evaluate(state)

        return state
