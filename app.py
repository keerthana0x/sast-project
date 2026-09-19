import os
import streamlit as st
import tempfile
# Import our core scanner functions from sast_engine.py
from sast_engine import scan_directory_recursively, verify_flaw_with_ai

# Page Configuration
st.set_page_config(
    page_title="Hybrid AI-SAST Auditor",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ Hybrid AI-SAST Vulnerability Engine")
st.caption("Local AST Scanning + Gemini AI Threat Verification")

# Sidebar for Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key_input = st.text_input(
        "Gemini API Key", 
        value=os.environ.get("GEMINI_API_KEY", ""), 
        type="password",
        help="Enter your Google AI Studio API key"
    )
    if api_key_input:
        os.environ["GEMINI_API_KEY"] = api_key_input
        st.success("API Key active!")
    else:
        st.warning("Please enter a Gemini API Key to run Stage 2 AI verification.")

# Main Tabs
tab1, tab2 = st.tabs(["📁 Upload & Scan Files", "📝 Direct Code Snippet Audit"])

# --- TAB 1: FILE / DIRECTORY UPLOADER ---
with tab1:
    st.subheader("Upload Python Files for Security Audit")
    uploaded_files = st.file_uploader("Choose .py files to scan", type=["py"], accept_multiple_files=True)

    if st.button("🚀 Run Full Security Scan", type="primary"):
        if not uploaded_files:
            st.error("Please upload at least one Python file.")
        elif not os.environ.get("GEMINI_API_KEY"):
            st.error("Missing Gemini API Key. Please set it in the sidebar.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                for uploaded_file in uploaded_files:
                    temp_file_path = os.path.join(temp_dir, uploaded_file.name)
                    with open(temp_file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())

                st.info("Stage 1: Running Local AST Scan...")
                candidates = scan_directory_recursively(temp_dir)
                st.write(f"🔍 Found **{len(candidates)}** candidate security sink(s).")

                if candidates:
                    st.info("Stage 2: Verifying threats with Gemini AI...")
                    progress_bar = st.progress(0)
                    verified_results = []

                    for idx, flaw in enumerate(candidates):
                        ai_result = verify_flaw_with_ai(flaw)
                        if ai_result and ai_result.is_real_vulnerability:
                            verified_results.append({"flaw": flaw, "ai": ai_result})
                        progress_bar.progress((idx + 1) / len(candidates))

                    st.subheader(f"📊 Audit Results ({len(verified_results)} Verified Threats)")

                    if not verified_results:
                        st.success("No real vulnerabilities confirmed. All candidates were false alarms!")
                    else:
                        for item in verified_results:
                            flaw = item["flaw"]
                            ai = item["ai"]
                            
                            severity_color = {
                                "High": "🔴",
                                "Medium": "🟠",
                                "Low": "🔵"
                            }.get(ai.severity, "⚪")

                            with st.expander(f"{severity_color} [{ai.severity}] {flaw.vulnerability_type} in {os.path.basename(flaw.filename)} (Line {flaw.line_number})"):
                                st.write(f"**AI Assessment:** {ai.explanation}")
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.caption("Vulnerable Code Snippet:")
                                    st.code(flaw.code_snippet, language="python")
                                with col2:
                                    st.caption("Recommended Patch:")
                                    st.code(ai.fixed_code, language="python")

# --- TAB 2: DIRECT SNIPPET AUDIT ---
with tab2:
    st.subheader("Test Code Snippet Instantly")
    snippet_code = st.text_area(
        "Paste Python Code:",
        value="import sqlite3\n\ndef handle_login(username):\n    conn = sqlite3.connect('app.db')\n    cursor = conn.cursor()\n    # SQL Injection Risk\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\n",
        height=180
    )

    if st.button("Analyze Snippet"):
        if not os.environ.get("GEMINI_API_KEY"):
            st.error("Missing Gemini API Key. Please set it in the sidebar.")
        else:
            with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
                tmp.write(snippet_code)
                tmp_path = tmp.name

            try:
                candidates = scan_directory_recursively(os.path.dirname(tmp_path))
                candidates = [c for c in candidates if os.path.abspath(c.filename) == os.path.abspath(tmp_path)]
                
                if not candidates:
                    st.success("No candidate vulnerabilities detected by local AST parser.")
                else:
                    for flaw in candidates:
                        ai_result = verify_flaw_with_ai(flaw)
                        if ai_result and ai_result.is_real_vulnerability:
                            st.error(f"🚨 Confirmed Threat: {flaw.vulnerability_type} [{ai_result.severity}]")
                            st.write(f"**Explanation:** {ai_result.explanation}")
                            st.code(ai_result.fixed_code, language="python")
                        else:
                            st.info("Candidate flagged locally, but AI verified it as a False Positive.")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)