# 🛡️ PhishGuard — Real-Time Phishing Detection with Human Override

**Course:** Large Language Models and Agentic AI  
**Problem Statement ID:** SIH25159  
**Primary Dataset:** PhishTank Open Threat Intelligence Dataset (`phishtank.org`)  

---

## 📌 Project Summary
PhishGuard is an autonomous **Multi-Agent Cybersecurity Pipeline** designed to detect phishing attacks in real time. Instead of relying on a black-box classifier, it uses specialized AI and deterministic agents to analyze:
1. **Header & Authentication Protocols (SPF / DKIM / DMARC)** and display-name spoofing.
2. **Threat Intelligence via PhishTank Ground-Truth DB** for verified malicious URLs.
3. **Domain Integrity & Typosquatting** (homoglyphs, Levenshtein distance, high-risk TLDs).
4. **LLM Cognitive Intent Analysis** (psychological urgency, fear, coercion, credential-harvesting call-to-actions).
5. **Supervising Triage Evaluator** producing transparent, chain-of-thought explanations.
6. **Human-in-the-Loop (HITL) Override System** allowing SOC analysts to review, audit, and override decisions on ambiguous or quarantined emails.

---

## 🚀 Quickstart Guide

### 1. Setup Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```
*(Get a free Gemini API key from [Google AI Studio](https://aistudio.google.com/) and paste it into `.env` or enter it directly in the Streamlit UI. If left empty, PhishGuard seamlessly uses its built-in local semantic heuristic engine).*

### 3. Launch the Interactive HITL Dashboard
```powershell
streamlit run app.py
```

### 🐳 Running with Docker
You can also run PhishGuard as an isolated container:
```bash
# Build and run with Docker Compose
docker compose up --build -d

# Access dashboard at: http://localhost:8501
```

---

## 📊 Key Features & Modules

* 🚀 **Working Pipeline Demo:** Live interactive tester in Tab 1 with preset test cases and explainable AI traces.
* 🧑‍⚖️ **Human Override Interface:** Tab 2 allows reviewers to inspect quarantined messages, read the agent's reasoning, and click **Release (False Positive)** or **Confirm Phishing**.
* 🔲 **Confusion Matrix & Metrics:** Tab 3 executes an automated benchmark across ground-truth phishing and legitimate emails, plotting the Confusion Matrix and reporting Accuracy, Precision, Recall, F1-Score, and Specificity.

---

## 👩‍💻 Author & Maintainer

* **Sonali Sinha** ([@SONALISINHA01](https://github.com/SONALISINHA01))
* **Repository:** [SONALISINHA01/Phishguard](https://github.com/SONALISINHA01/Phishguard)
