import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
PHISHTANK_DIR = DATA_DIR / "phishtank"
TEST_EMAILS_DIR = DATA_DIR / "test_emails"
MEMORY_DB_PATH = BASE_DIR / "hitl_memory.json"

# PhishTank dataset path
PHISHTANK_CSV = os.getenv("PHISHTANK_DATA_PATH", str(PHISHTANK_DIR / "verified_online.csv"))

# API Keys
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Fallback to Streamlit secrets if running inside Streamlit
if not GEMINI_API_KEY:
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
            GEMINI_API_KEY = str(st.secrets["GEMINI_API_KEY"])
    except Exception:
        pass

# Risk Thresholds (0 - 100)
SAFE_THRESHOLD = float(os.getenv("SAFE_THRESHOLD", "30.0"))
QUARANTINE_THRESHOLD = float(os.getenv("QUARANTINE_THRESHOLD", "75.0"))

# Commonly impersonated brands for lookalike detection
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "dropbox", "dhl", "fedex", "irs", "docuSign", "coinbase", "binance"
]
