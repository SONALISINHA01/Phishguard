import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from src.config import MEMORY_DB_PATH
from src.agents.state import AgentState

class MemoryStore:
    """
    Episodic Memory and Human-in-the-Loop Audit Store.
    Persists email triage decisions, quarantine states, and analyst overrides.
    """

    def __init__(self, db_path: str = str(MEMORY_DB_PATH)):
        self.db_path = db_path
        self._ensure_db()

    def _ensure_db(self):
        if not os.path.exists(self.db_path):
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump({"records": [], "overrides": []}, f, indent=2)

    def _read_data(self) -> Dict[str, Any]:
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"records": [], "overrides": []}

    def _write_data(self, data: Dict[str, Any]):
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_state(self, state: AgentState):
        """Saves a processed email state to the audit store."""
        data = self._read_data()
        existing = [r for r in data["records"] if r["email_id"] != state.email_id]
        rec = state.to_dict()
        rec["processed_at"] = datetime.now().isoformat()
        existing.append(rec)
        data["records"] = existing
        self._write_data(data)

    def record_override(
        self,
        email_id: str,
        analyst_action: str, # "RELEASE_TO_INBOX" or "CONFIRM_PHISHING"
        reviewer_notes: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Records human override action for a quarantined or flagged email.
        """
        data = self._read_data()
        matched = None
        for r in data["records"]:
            if r["email_id"] == email_id:
                r["is_overridden"] = True
                r["human_override_action"] = analyst_action
                r["reviewer_notes"] = reviewer_notes
                r["reviewed_at"] = datetime.now().isoformat()
                matched = r
                break

        if matched:
            data["overrides"].append({
                "email_id": email_id,
                "action": analyst_action,
                "notes": reviewer_notes,
                "timestamp": datetime.now().isoformat(),
                "original_action": matched.get("action"),
                "sender": matched.get("sender")
            })
            self._write_data(data)
        return matched

    def get_all_records(self) -> List[Dict[str, Any]]:
        return self._read_data().get("records", [])

    def get_quarantined_records(self) -> List[Dict[str, Any]]:
        """Returns records that are currently in quarantine and need review."""
        records = self.get_all_records()
        return [r for r in records if r.get("action") in ["QUARANTINE", "FLAG"] and not r.get("is_overridden")]

    def get_override_history(self) -> List[Dict[str, Any]]:
        return self._read_data().get("overrides", [])
