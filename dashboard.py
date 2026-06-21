import streamlit as st
import os
import json
import time

from app import (
    FeatureExtractor,
    PersonaClassifier,
    SandboxParser,
    PDFReportBuilder,
    CONFIG
)

# =====================================================================
# STREAMLIT CONFIG
# =====================================================================

st.set_page_config(page_title="MazeCryptX Dashboard", layout="wide")
st.title("🛡 MazeCryptX – Adaptive Honeypot & Forensic Intelligence Dashboard")


# =====================================================================
# LOAD EVENTS
# =====================================================================
def load_events():
    events = []
    if os.path.exists(CONFIG["EVENTS_FILE"]):
        with open(CONFIG["EVENTS_FILE"], "r") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except:
                    pass
    return events


# =====================================================================
# TABS LAYOUT
# =====================================================================

tabs = st.tabs([
    "📡 Live Attacks",
    "💻 Session Replay",
    "🧪 Sandbox Output",
    "🧠 Persona Analysis",
    "📄 Forensic PDF"
])


# =====================================================================
# TAB 1 — LIVE ATTACK FEED
# =====================================================================
with tabs[0]:
    st.header("📡 Live Attack Feed")
    events = load_events()
    events_sorted = sorted(
        events,
        key=lambda x: x.get("timestamp", ""),
        reverse=True   # 🔥 IMPORTANT
    )

    if events_sorted:
        st.dataframe(events_sorted)
    else:
        st.info("No events recorded yet.")


# =====================================================================
# TAB 2 — SESSION REPLAY
# =====================================================================
with tabs[1]:
    st.header("💻 SSH Session Replay")

    events = load_events()
    ips = list({e["ip"] for e in events if "ip" in e})

    selected_ip = st.selectbox("Select Attacker IP", ips)

    if selected_ip:
        session_cmds = [
            e for e in events 
            if e.get("ip") == selected_ip and e.get("type") == "ssh_command"
        ]

        if session_cmds:
            for e in session_cmds:
                st.markdown(f"**{e['timestamp']}** — `{e['command']}`")
        else:
            st.info("No SSH commands found for this IP.")


# =====================================================================
# TAB 3 — SANDBOX LOGS
# =====================================================================
with tabs[2]:
    st.header("🧪 Sandbox Execution Logs")

    log_files = os.listdir(CONFIG["SANDBOX_LOGS"])
    log_files = [f for f in log_files if f.endswith(".log")]

    if log_files:
        selected_file = st.selectbox("Select Sandbox Log", log_files)

        if selected_file:
            log_path = os.path.join(CONFIG["SANDBOX_LOGS"], selected_file)
            with open(log_path, "r") as f:
                content = f.read()

            st.subheader("Raw Output")
            st.code(content)

            iocs = SandboxParser.parse_log(content)
            st.subheader("Extracted IoCs")
            st.json(iocs)
    else:
        st.info("No sandbox logs yet.")


# =====================================================================
# TAB 4 — ATTACKER PERSONA ANALYSIS (ML)
# =====================================================================
with tabs[3]:
    st.header("🧠 Attacker Persona Analysis")

    if st.button("Train ML Model"):
        results = PersonaClassifier().train()
        if results:
            st.success("Model trained successfully.")
            st.json(results)
        else:
            st.error("Not enough attacker data to train ML model.")

    events = load_events()
    ips = list({e["ip"] for e in events if "ip" in e})

    selected_ip = st.selectbox("Predict Persona for IP", ips)

    if st.button("Predict Persona"):
        persona = PersonaClassifier().predict(selected_ip)
        st.write(f"### Persona: **{persona}**")


# =====================================================================
# TAB 5 — FORENSIC PDF REPORT
# =====================================================================
with tabs[4]:
    st.header("📄 Generate Forensic Report")

    events = load_events()
    ips = list({e["ip"] for e in events if "ip" in e})

    selected_ip = st.selectbox("Select IP for Forensic Report", ips)

    if selected_ip and st.button("Generate PDF"):
        pdf_path = PDFReportBuilder().generate_pdf(selected_ip)
        st.success(f"PDF Report generated: {pdf_path}")

        with open(pdf_path, "rb") as f:
            st.download_button(
                "Download Report",
                f,
                file_name=os.path.basename(pdf_path)
            )
