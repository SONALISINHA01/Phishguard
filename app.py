import os
import json
import streamlit as st
import pandas as pd
from pathlib import Path

# Import PhishGuard modules
from src.config import SAFE_THRESHOLD, QUARANTINE_THRESHOLD, PHISHTANK_CSV
from src.agents.pipeline import PhishGuardPipeline
from src.hitl.memory_store import MemoryStore
from src.evaluation.evaluator import BenchmarkEvaluator

st.set_page_config(
    page_title="PhishGuard — Real-Time Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished cybersecurity UI
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 800; color: #1E3A8A; margin-bottom: 0.2rem; }
    .sub-title { font-size: 1rem; color: #4B5563; margin-bottom: 1.5rem; }
    .metric-card { background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; }
    .badge-safe { background-color: #DCFCE7; color: #166534; padding: 4px 10px; border-radius: 12px; font-weight: 600; }
    .badge-flag { background-color: #FEF3C7; color: #92400E; padding: 4px 10px; border-radius: 12px; font-weight: 600; }
    .badge-quarantine { background-color: #FEE2E2; color: #991B1B; padding: 4px 10px; border-radius: 12px; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# Initialize Session State & Singletons
if "memory_store" not in st.session_state:
    st.session_state.memory_store = MemoryStore()

if "api_key" not in st.session_state:
    st.session_state.api_key = os.getenv("GEMINI_API_KEY", "")

# Sidebar Controls
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("PhishGuard Controls")
    st.caption("SIH25159 • LLM & Agentic AI")

    st.markdown("---")
    st.subheader("🔑 LLM Configuration")
    api_key_input = st.text_input(
        "Google Gemini API Key",
        value=st.session_state.api_key,
        type="password",
        help="Free key from https://aistudio.google.com/. Leave empty to use local semantic engine."
    )
    if api_key_input != st.session_state.api_key:
        st.session_state.api_key = api_key_input
        st.success("API Key updated!")

    st.markdown("---")
    st.subheader("⚙️ Defense Thresholds")
    safe_thresh = st.slider("Safe Threshold (< X Deliver)", 10, 50, int(SAFE_THRESHOLD), 5)
    quarantine_thresh = st.slider("Quarantine Threshold (> X Block)", 50, 90, int(QUARANTINE_THRESHOLD), 5)

    st.markdown("---")
    st.markdown("**Threat Intel Status:**")
    if os.path.exists(PHISHTANK_CSV):
        st.success("✅ PhishTank DB Loaded")
    else:
        st.warning("⚠️ Using Seed PhishTank Data")

# Instantiate Pipeline
pipeline = PhishGuardPipeline(gemini_api_key=st.session_state.api_key)
pipeline.triage_agent.safe_threshold = float(safe_thresh)
pipeline.triage_agent.quarantine_threshold = float(quarantine_thresh)

# Header Title
st.markdown('<div class="main-title">🛡️ PhishGuard: Real-Time Phishing Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Autonomous Agentic Email Security with Explainable Reasoning and Human-in-the-Loop Override</div>', unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs([
    "📥 Real-Time Pipeline Demo",
    "🧑‍⚖️ Human-in-the-Loop Override Queue",
    "📊 Benchmark & Confusion Matrix"
])

# ==============================================================================
# TAB 1: REAL-TIME PIPELINE DEMO
# ==============================================================================
with tab1:
    st.subheader("Live Inbound Email Analysis")
    
    # Preset quick-load examples
    preset_choice = st.selectbox(
        "Quick Load Sample Email:",
        [
            "Custom Email Input",
            "🚨 Phishing: Urgent PayPal Suspension & Malicious Link",
            "🚨 Phishing: Netflix Payment Failure with Typosquatted Domain",
            "🚨 Phishing: Office 365 Password Expiry with Failed SPF/DKIM",
            "✅ Legitimate: GitHub Notification with Authenticated DKIM",
            "✅ Legitimate: Amazon Order Confirmation"
        ]
    )

    default_sender = ""
    default_subject = ""
    default_body = ""
    default_auth = "spf=pass dkim=pass dmarc=pass"

    if "PayPal" in preset_choice:
        default_sender = "PayPal Support <service@paypal-security-account-verification.com>"
        default_subject = "Urgent: Your PayPal Account Has Been Temporarily Restricted"
        default_body = "Dear Customer,\n\nWe detected suspicious login activity from an unknown IP address. You must verify your credentials within 24 hours to avoid suspension.\n\nVerify immediately: http://paypal-security-account-verification.com/login\n\nPayPal Security Team"
        default_auth = "spf=fail dkim=fail"
    elif "Netflix" in preset_choice:
        default_sender = "Netflix Billing <update@netflix-billing-update-required.net>"
        default_subject = "Action Required: Update your streaming payment method"
        default_body = "Hi Member,\n\nWe were unable to process your subscription renewal. Update your card now to continue watching:\nhttp://netflix-billing-update-required.net/signin\n\nNetflix Support"
        default_auth = "spf=softfail dkim=none"
    elif "Office 365" in preset_choice:
        default_sender = "IT Helpdesk <admin@microsoft-office365-pass-reset.org>"
        default_subject = "Final Warning: Domain Password Expiring Today"
        default_body = "Attention,\n\nYour Office 365 password expires in 2 hours. Click below to keep your current credentials:\nhttps://microsoft-office365-pass-reset.org/auth\n\nGlobal IT Administrator"
        default_auth = "spf=fail dkim=fail dmarc=fail"
    elif "GitHub" in preset_choice:
        default_sender = "GitHub Notifications <notifications@github.com>"
        default_subject = "[GitHub] Build succeeded on main branch"
        default_body = "Run completed successfully for commit a8f12c9.\nView build logs: https://github.com/sonali/phishguard/actions\n\nGitHub Support"
        default_auth = "spf=pass dkim=pass dmarc=pass"
    elif "Amazon" in preset_choice:
        default_sender = "Amazon Orders <order-update@amazon.com>"
        default_subject = "Your Amazon.com order #114-9912 has shipped"
        default_body = "Hello,\n\nYour order has shipped. Track package at https://www.amazon.com/gp/your-account/order-history\n\nThank you for choosing Amazon."
        default_auth = "spf=pass dkim=pass dmarc=pass"

    col_in1, col_in2 = st.columns([1, 1])
    with col_in1:
        sender_input = st.text_input("Sender (From:)", value=default_sender, placeholder="Display Name <user@domain.com>")
        subject_input = st.text_input("Subject:", value=default_subject, placeholder="Email subject line")
        auth_input = st.text_input("Authentication-Results Header:", value=default_auth, help="Simulated or real SPF/DKIM header string")

    with col_in2:
        body_input = st.text_area("Email Body Content:", value=default_body, height=160, placeholder="Paste email plain text or HTML here...")

    if st.button("🚀 Analyze Email with Agentic Pipeline", type="primary", use_container_width=True):
        if not body_input.strip() and not sender_input.strip():
            st.warning("Please provide email details before running analysis.")
        else:
            with st.spinner("Multi-agent system evaluating headers, links, PhishTank feeds, and psychological intent..."):
                headers = {"Authentication-Results": auth_input}
                state = pipeline.process_email(
                    sender=sender_input,
                    subject=subject_input,
                    body=body_input,
                    headers=headers
                )
                # Save to audit memory
                st.session_state.memory_store.save_state(state)

            st.markdown("---")
            # Result Overview Header
            res_col1, res_col2, res_col3 = st.columns([1, 1, 1])
            with res_col1:
                st.metric("Composite Risk Score", f"{state.risk_score} / 100")
            with res_col2:
                if state.action == "DELIVER":
                    st.markdown("### Action: <span class='badge-safe'>DELIVER (SAFE)</span>", unsafe_allow_html=True)
                elif state.action == "FLAG":
                    st.markdown("### Action: <span class='badge-flag'>FLAG (SUSPICIOUS)</span>", unsafe_allow_html=True)
                else:
                    st.markdown("### Action: <span class='badge-quarantine'>QUARANTINE (MALICIOUS)</span>", unsafe_allow_html=True)
            with res_col3:
                st.metric("Threat Category", state.threat_category)

            # Explainable AI Breakdown Tabs
            st.markdown("### 🔍 Explainable Multi-Agent Reasoning Trace")
            
            exp_col1, exp_col2 = st.columns([1, 1])
            with exp_col1:
                with st.expander("📧 1. Header & Authentication Agent", expanded=True):
                    h_res = state.header_verdict
                    st.write(f"**From Domain:** `{h_res.get('sender_domain')}`")
                    st.write(f"**SPF:** `{h_res.get('spf_status')}` | **DKIM:** `{h_res.get('dkim_status')}` | **DMARC:** `{h_res.get('dmarc_status')}`")
                    st.write(f"**Header Risk:** {h_res.get('header_risk_score')}/100")
                    if h_res.get("flags"):
                        for f in h_res["flags"]:
                            st.error(f)

                with st.expander("🚨 2. Threat Intel & PhishTank Agent", expanded=True):
                    pt_res = state.phishtank_verdict
                    st.write(f"**URLs Extracted:** {pt_res.get('total_urls_scanned')}")
                    st.write(f"**PhishTank Match:** `{'YES - MALICIOUS' if pt_res.get('threat_detected') else 'NO MATCH'}`")
                    st.write(f"**Threat Severity:** `{pt_res.get('highest_threat')}`")
                    for finding in pt_res.get("url_findings", []):
                        if finding["is_match"]:
                            st.error(f"🔴 `{finding['url']}`: {finding['details']}")
                        else:
                            st.success(f"🟢 `{finding['url']}`: {finding['details']}")

            with exp_col2:
                with st.expander("🌐 3. Domain Integrity & Typosquatting Agent", expanded=True):
                    dom_res = state.domain_verdict
                    st.write(f"**Max Domain Risk:** {dom_res.get('max_domain_risk')}/100")
                    if dom_res.get("flags"):
                        for f in dom_res["flags"]:
                            st.warning(f)
                    else:
                        st.write("No brand typosquatting or high-risk TLDs detected.")

                with st.expander("🧠 4. LLM Semantic Intent Agent", expanded=True):
                    int_res = state.intent_verdict
                    st.write(f"**Engine:** `{int_res.get('analysis_engine')}`")
                    st.write(f"**Urgency Score:** {int_res.get('urgency_score')}/100 | **Deceit Score:** {int_res.get('deceit_score')}/100")
                    st.write(f"**Intent Classification:** `{int_res.get('intent_type')}`")
                    st.markdown(f"**Rationale:**\n> {int_res.get('rationale')}")

            # Overall Summary Box
            st.info(state.explanation)

# ==============================================================================
# TAB 2: HUMAN-IN-THE-LOOP OVERRIDE QUEUE
# ==============================================================================
with tab2:
    st.subheader("Human-in-the-Loop (HITL) Reviewer Dashboard")
    st.caption("Inspect emails flagged or quarantined by the agentic pipeline. A human reviewer can override false positives or confirm malicious attacks.")

    quarantine_queue = st.session_state.memory_store.get_quarantined_records()

    if not quarantine_queue:
        st.success("🎉 Quarantine queue is clear! No pending emails require human review.")
    else:
        st.write(f"**Pending Review:** {len(quarantine_queue)} message(s)")
        for idx, rec in enumerate(quarantine_queue):
            with st.container():
                st.markdown(f"#### 📬 Email ID: `{rec['email_id']}` — {rec['subject']}")
                col_m1, col_m2, col_m3 = st.columns([1, 1, 2])
                with col_m1:
                    st.write(f"**Sender:** `{rec['sender']}`")
                with col_m2:
                    st.write(f"**Agent Risk Score:** `{rec['risk_score']}/100` (`{rec['action']}`)")
                with col_m3:
                    st.write(f"**Extracted URLs:** `{', '.join(rec.get('extracted_urls', [])) or 'None'}`")

                with st.expander("📄 View Full Email Content & Reasoning"):
                    st.text_area("Body Text:", rec.get("body_text", ""), height=100, disabled=True, key=f"body_{idx}")
                    st.markdown(rec.get("explanation", ""))

                # Reviewer Actions
                col_act1, col_act2, col_act3 = st.columns([1, 1, 2])
                with col_act1:
                    if st.button("🟢 Override: False Positive (Release)", key=f"rel_{rec['email_id']}", use_container_width=True):
                        st.session_state.memory_store.record_override(
                            email_id=rec["email_id"],
                            analyst_action="RELEASE_TO_INBOX",
                            reviewer_notes="Analyst determined message is legitimate business communication."
                        )
                        st.success(f"Email {rec['email_id']} released to recipient inbox!")
                        st.rerun()

                with col_act2:
                    if st.button("🔴 Confirm: True Positive (Block)", key=f"blk_{rec['email_id']}", use_container_width=True):
                        st.session_state.memory_store.record_override(
                            email_id=rec["email_id"],
                            analyst_action="CONFIRM_PHISHING",
                            reviewer_notes="Analyst confirmed malicious phishing attack."
                        )
                        st.error(f"Email {rec['email_id']} permanently blocked!")
                        st.rerun()

                st.markdown("---")

    # Audit Trail of Past Human Overrides
    st.subheader("📜 Human Override Audit Trail")
    overrides = st.session_state.memory_store.get_override_history()
    if overrides:
        df_overrides = pd.DataFrame(overrides)
        st.dataframe(df_overrides, use_container_width=True)
    else:
        st.write("No overrides logged yet.")

# ==============================================================================
# TAB 3: BENCHMARK & CONFUSION MATRIX DELIVERABLE
# ==============================================================================
with tab3:
    st.subheader("Automated Benchmark Evaluation & Confusion Matrix")
    st.caption("Deliverable Requirement: Evaluates PhishGuard on ground-truth benchmark emails and PhishTank verified samples.")

    dataset_path = Path("data/test_emails/benchmark_dataset.json")
    if dataset_path.exists():
        with open(dataset_path, "r", encoding="utf-8") as f:
            test_data = json.load(f)
        st.write(f"Loaded benchmark dataset containing **{len(test_data)} ground-truth labeled emails**.")
    else:
        st.error("Benchmark dataset not found.")
        test_data = []

    if st.button("📊 Run Full Benchmark & Generate Confusion Matrix", type="primary"):
        with st.spinner("Running agentic pipeline over benchmark samples..."):
            evaluator = BenchmarkEvaluator(pipeline=pipeline)
            eval_results = evaluator.evaluate_batch(test_data)

        metrics = eval_results["metrics"]
        cm = eval_results["confusion_matrix"]

        # Display Metrics Cards
        st.markdown("### 🎯 Classification Metrics")
        m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
        m_col1.metric("Accuracy", f"{metrics['accuracy']}%")
        m_col2.metric("Precision", f"{metrics['precision']}%")
        m_col3.metric("Recall (Sensitivity)", f"{metrics['recall']}%")
        m_col4.metric("F1-Score", f"{metrics['f1_score']}%")
        m_col5.metric("Specificity", f"{metrics['specificity']}%")

        # Confusion Matrix Display
        st.markdown("### 🔲 Confusion Matrix")
        cm_col1, cm_col2 = st.columns([1, 1])

        with cm_col1:
            matrix_df = pd.DataFrame(
                cm["matrix"],
                index=["Actual Legitimate", "Actual Phishing"],
                columns=["Pred. Legitimate", "Pred. Phishing"]
            )
            st.dataframe(matrix_df.style.background_gradient(cmap="Blues"), use_container_width=True)

        with cm_col2:
            st.markdown(f"""
            * **True Positives (TP):** `{cm['tp']}` *(Phishing correctly caught & quarantined)*
            * **True Negatives (TN):** `{cm['tn']}` *(Legitimate emails safely delivered)*
            * **False Positives (FP):** `{cm['fp']}` *(Clean emails mistakenly flagged)*
            * **False Negatives (FN):** `{cm['fn']}` *(Phishing emails missed — critically low)*
            """)

        # Detailed Predictions Table
        st.markdown("### 📋 Sample-by-Sample Evaluation Audit")
        details_df = pd.DataFrame(eval_results["detailed_results"])
        st.dataframe(
            details_df[["id", "subject", "actual", "predicted", "risk_score", "action", "outcome"]],
            use_container_width=True
        )
