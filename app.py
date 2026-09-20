import os
import streamlit as st
import hmac
from sast_engine import scan_directory_recursively, verify_flaw_with_ai, run_ast_scanner

# 1. Page Config
st.set_page_config(
    page_title="Hybrid AI-SAST Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Authentication Function
def check_password():
    def password_entered():
        user = st.session_state.get("username", "")
        pwd = st.session_state.get("password", "")
        valid_users = {
            "admin": "cyber2026",
            "evaluator": "sast_demo_2026"
        }
        if user in valid_users and hmac.compare_digest(pwd, valid_users[user]):
            st.session_state["password_correct"] = True
            st.session_state["current_user"] = user
            if "password" in st.session_state:
                del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if st.session_state.get("password_correct", False):
        return True

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🛡️ Hybrid AI-SAST Engine</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>🔐 Cybersecurity Portal Access</h3>", unsafe_allow_html=True)
        st.caption("<p style='text-align: center;'>Authenticate to access the Static Application Security Testing Suite.</p>", unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.text_input("Username", key="username")
            st.text_input("Password", type="password", key="password")
            submit = st.form_submit_button("Log In", use_container_width=True)

        if st.session_state.get("password_correct") == False:
            st.error("❌ Invalid Username or Password")

    return False

# 3. Main Application Dashboard
if check_password():
    with st.sidebar:
        st.title("SAST Control Panel")
        st.write(f"👤 Active User: **{st.session_state.get('current_user', 'User')}**")
        
        gemini_key = os.getenv("GEMINI_API_KEY") or st.secrets.get("GEMINI_API_KEY", None)
        if gemini_key:
            st.success("🟢 Gemini API Key Loaded")
        else:
            st.warning("⚠️ Gemini API Key Missing in Secrets")
            
        st.markdown("---")
        if st.button("🚪 Log Out", use_container_width=True):
            st.session_state["password_correct"] = False
            st.rerun()

    st.title("🛡️ Hybrid AI-SAST Security Engine")
    st.caption("Combining AST Rule-Based Static Analysis with Google Gemini AI Verification")
    
    tab1, tab2, tab3 = st.tabs(["📝 Code Snippet Audit", "📁 Directory Scan", "ℹ️ About Engine"])

    with tab1:
        st.subheader("Interactive Snippet Analysis")
        sample_code = """import sqlite3

def login_user(username, password):
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
# Unsafe raw string query formatting
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
return cursor.fetchone()
"""
        code_input = st.text_area("Python Source Code", value=sample_code, height=220)

        if st.button("🔍 Run Security Audit", type="primary"):
            if not code_input.strip():
                st.warning("Please paste some code to analyze.")
            else:
                with st.status("Analyzing code snippet...", expanded=True) as status:
                    st.write("⚙️ Stage 1: Running AST Rule Engine...")
                    temp_filename = "_temp_snippet.py"
                    with open(temp_filename, "w", encoding="utf-8") as f:
                        f.write(code_input)

                    raw_findings = run_ast_scanner(temp_filename)
                    if os.path.exists(temp_filename):
                        os.remove(temp_filename)

                    st.write("🤖 Stage 2: Performing AI Verification via Gemini...")
                    
                    if not raw_findings:
                        status.update(label="Audit Complete: No basic flaws detected!", state="complete")
                        st.success("✅ No preliminary vulnerabilities detected by rule engine.")
                    else:
                        status.update(label="Audit Complete: Vulnerabilities Detected!", state="complete")
                        
                        m1, m2, m3 = st.columns(3)
                        m1.metric("AST Findings", len(raw_findings))
                        m2.metric("Scan Status", "Completed")
                        m3.metric("AI Engine", "Gemini Enabled")
                        
                        st.divider()

                        for flaw in raw_findings:
                            st.error(f"🚨 **Potential Issue Detected:** {flaw.get('flaw_type', 'Security Risk')}")
                            st.write(f"**Line Number:** {flaw.get('line', 'N/A')}")
                            st.code(flaw.get('code_snippet', ''), language="python")

                            ai_result = verify_flaw_with_ai(
                                flaw_type=flaw.get('flaw_type'),
                                snippet=flaw.get('code_snippet'),
                                line_no=flaw.get('line')
                            )

                            if ai_result:
                                st.markdown("#### 🤖 AI Vulnerability Analysis")
                                st.write(f"**Is Real Vulnerability:** {'Yes 🚨' if ai_result.is_vulnerability else 'False Positive 🟢'}")
                                st.write(f"**Explanation:** {ai_result.explanation}")
                                
                                col_orig, col_fixed = st.columns(2)
                                with col_orig:
                                    st.markdown("##### ❌ Flagged Code")
                                    st.code(flaw.get('code_snippet', ''), language="python")
                                with col_fixed:
                                    st.markdown("##### ✅ AI Remediated Code")
                                    st.code(ai_result.remediated_code, language="python")

    with tab2:
        st.subheader("Repository Directory Scan")
        target_dir = st.text_input("Enter Repository Path", value=".")

        if st.button("🚀 Scan Directory"):
            if not os.path.exists(target_dir):
                st.error("Directory path does not exist.")
            else:
                with st.spinner("Scanning directory files..."):
                    results = scan_directory_recursively(target_dir)

                if not results:
                    st.success("✅ No vulnerabilities detected in directory.")
                else:
                    st.warning(f"⚠️ Found potential security issues across {len(results)} file(s).")
                    for item in results:
                        with st.expander(f"📁 File: `{item['file']}`"):
                            for flaw in item.get('findings', []):
                                st.markdown(f"**Flaw:** `{flaw.get('flaw_type')}` | **Line:** {flaw.get('line')}")
                                st.code(flaw.get('code_snippet'), language="python")

    with tab3:
        st.subheader("About the Hybrid AI-SAST Engine")
        st.markdown("""
        ### Architecture & Methodology
        This application combines deterministic rule-based Static Application Security Testing (SAST) with GenAI-driven reasoning:

        1. **Stage 1 — AST Pattern Matcher:** Analyzes Python Abstract Syntax Trees (AST) to identify pattern-based security anti-patterns.
        2. **Stage 2 — GenAI Verification & Remediation:** Sends flagged patterns to Google Gemini AI to verify context and produce secure refactored code.

        ---
        **Developed for B.E. Cybersecurity Capstone Project**
        """)
