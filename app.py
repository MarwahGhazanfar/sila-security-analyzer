import streamlit as st
import pandas as pd
import os
import altair as alt

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="SILA Security Analyzer", layout="wide")
st.title("SILA Security Analyzer")
st.subheader("Cybersecurity Log Monitoring & Threat Detection System")

# ---------------- FILES & DATA ----------------
LOG_FILE = "logs.csv"
BLOCKED_FILE = "blocked_ips.txt"
sev_text = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Initialize logs with some default entries
default_logs = [
    {"Time": 930, "IP": "192.168.1.10", "User": "alice", "Event": "LOGIN_FAIL", "Severity": 2},
    {"Time": 945, "IP": "192.168.1.11", "User": "bob", "Event": "MALWARE_DETECTED", "Severity": 4},
    {"Time": 1015, "IP": "192.168.1.12", "User": "charlie", "Event": "FILE_DELETE", "Severity": 3},
    {"Time": 1030, "IP": "192.168.1.13", "User": "dave", "Event": "CONFIG_CHANGE", "Severity": 2},
]

def init_logs():
    if not os.path.exists(LOG_FILE):
        df = pd.DataFrame(default_logs)
        df.to_csv(LOG_FILE, index=False)

def load_logs():
    init_logs()
    return pd.read_csv(LOG_FILE)

def save_logs(df):
    df.to_csv(LOG_FILE, index=False)

def load_blocked_ips():
    if not os.path.exists(BLOCKED_FILE):
        return set()
    with open(BLOCKED_FILE) as f:
        return set(i.strip() for i in f)

def block_ip(ip):
    with open(BLOCKED_FILE, "a") as f:
        f.write(ip + "\n")

# ---------------- SESSION STATE ----------------
if "logs" not in st.session_state:
    st.session_state.logs = load_logs()
if "blocked" not in st.session_state:
    st.session_state.blocked = load_blocked_ips()

# ---------------- TABS ----------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Log Management", 
    "View Logs", 
    "Priority Threats", 
    "Suspicious IPs", 
    "Time-Based Analysis"
])

# ---------------- LOG MANAGEMENT ----------------
with tab1:
    st.header("Add New Log")
    with st.form("add_log", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            time = st.text_input("Time (HHMM)")
            ip = st.text_input("IP Address")
            user = st.text_input("Username")
        with col2:
            event = st.selectbox("Event Type", ["LOGIN_FAIL", "FILE_DELETE", "MALWARE_DETECTED", "CONFIG_CHANGE"])
            severity = st.selectbox("Severity", [1, 2, 3, 4])
        submit = st.form_submit_button("Add Log")

        if submit:
            try:
                time = int(time)
                if ip in st.session_state.blocked:
                    st.error(f"IP {ip} is blocked! Cannot add log.")
                else:
                    new_log = {"Time": time, "IP": ip, "User": user, "Event": event, "Severity": severity}
                    st.session_state.logs = pd.concat(
                        [st.session_state.logs, pd.DataFrame([new_log])], ignore_index=True
                    )
                    save_logs(st.session_state.logs)
                    st.success("Log added successfully!")

                    if event == "LOGIN_FAIL":
                        count = st.session_state.logs[
                            (st.session_state.logs["IP"] == ip) &
                            (st.session_state.logs["Event"] == "LOGIN_FAIL")
                        ].shape[0]
                        if count >= 3 and ip not in st.session_state.blocked:
                            block_ip(ip)
                            st.session_state.blocked.add(ip)
                            st.warning(f"IP {ip} is now blocked.")
            except:
                st.error("Invalid time! Use HHMM format.")

# ---------------- VIEW LOGS ----------------
with tab2:
    st.header("All Logs")
    df = st.session_state.logs.copy()
    df["Severity"] = df["Severity"].map(sev_text)
    st.dataframe(df, use_container_width=True)

    # CSV export
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV", csv, "logs.csv", "text/csv")

# ---------------- PRIORITY THREATS ----------------
with tab3:
    st.header("Priority Threats (Severity ? 3)")
    df = st.session_state.logs[st.session_state.logs["Severity"] >= 3].copy()
    df["Severity"] = df["Severity"].map(sev_text)
    st.dataframe(df, use_container_width=True)

    if not df.empty:
        chart = alt.Chart(df).mark_bar().encode(
            x='Event',
            y='Severity',
            color='Event'
        )
        st.altair_chart(chart, use_container_width=True)

# ---------------- SUSPICIOUS IPs ----------------
with tab4:
    st.header("Suspicious IPs (? 3 Attempts)")
    suspicious = st.session_state.logs["IP"].value_counts()
    suspicious = suspicious[suspicious >= 3]
    st.table(suspicious)

# ---------------- TIME-BASED ANALYSIS ----------------
with tab5:
    st.header("Time-Based Log Filtering")
    start = st.text_input("Start Time (HHMM)")
    end = st.text_input("End Time (HHMM)")
    if st.button("Filter Logs"):
        try:
            start, end = int(start), int(end)
            df = st.session_state.logs[
                (st.session_state.logs["Time"] >= start) &
                (st.session_state.logs["Time"] <= end)
            ].copy()
            df["Severity"] = df["Severity"].map(sev_text)
            st.dataframe(df, use_container_width=True)
        except:
            st.error("Invalid time input")


