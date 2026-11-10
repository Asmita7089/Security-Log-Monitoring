import streamlit as st
import pandas as pd

from log_parser import parse_logs
from detection_engine import (
    detect_suspicious_activity,
    detect_success_after_failures
)
from database import (
    create_tables,
    save_events,
    save_alerts,
    get_events,
    get_alerts
)


st.set_page_config(
    page_title="Security Log Monitor",
    page_icon="🔐",
    layout="wide"
)


create_tables()


st.title("🔐 Security Log Monitoring & Suspicious Activity Detection")
st.caption("Python-based security event monitoring and rule-based threat detection")


# Load logs
df = parse_logs("sample_logs.txt")

# Detect alerts
failed_login_alerts = detect_suspicious_activity(df)
success_after_failure_alerts = detect_success_after_failures(df)


# Combine alerts
alerts = []

for _, row in failed_login_alerts.iterrows():
    alerts.append({
        "ip_address": row["ip_address"],
        "username": row["username"],
        "alert_type": row["alert_type"],
        "severity": row["severity"],
        "details": f"{row['failed_attempts']} failed login attempts detected"
    })


for _, row in success_after_failure_alerts.iterrows():
    alerts.append({
        "ip_address": row["ip_address"],
        "username": row["username"],
        "alert_type": row["alert_type"],
        "severity": row["severity"],
        "details": (
            f"{row['failed_attempts_before_success']} failed attempts "
            "followed by successful login"
        )
    })


alerts_df = pd.DataFrame(alerts)


# Save data
save_events(df)

if not alerts_df.empty:
    save_alerts(alerts_df)


# Sidebar
st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select Page",
    [
        "Dashboard",
        "Security Events",
        "Alerts",
        "IP Analysis"
    ]
)


# -------------------------
# DASHBOARD
# -------------------------

if page == "Dashboard":

    st.header("Security Dashboard")

    total_events = len(df)

    successful_logins = len(
        df[df["event"] == "LOGIN_SUCCESS"]
    )

    failed_logins = len(
        df[df["event"] == "LOGIN_FAILED"]
    )

    total_alerts = len(alerts_df)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)
    col2.metric("Successful Logins", successful_logins)
    col3.metric("Failed Logins", failed_logins)
    col4.metric("Security Alerts", total_alerts)

    st.divider()

    st.subheader("Event Distribution")

    event_counts = df["event"].value_counts()

    st.bar_chart(event_counts)

    st.subheader("Security Alerts")

    if alerts_df.empty:
        st.success("No suspicious activity detected.")
    else:
        st.dataframe(
            alerts_df,
            use_container_width=True
        )


# -------------------------
# SECURITY EVENTS
# -------------------------

elif page == "Security Events":

    st.header("Security Events")

    st.write(
        "Parsed authentication events collected from the log file."
    )

    st.dataframe(
        df,
        use_container_width=True
    )


# -------------------------
# ALERTS
# -------------------------

elif page == "Alerts":

    st.header("Detected Security Alerts")

    if alerts_df.empty:

        st.success("No alerts detected.")

    else:

        high_alerts = alerts_df[
            alerts_df["severity"] == "High"
        ]

        st.metric(
            "High Severity Alerts",
            len(high_alerts)
        )

        st.dataframe(
            alerts_df,
            use_container_width=True
        )


# -------------------------
# IP ANALYSIS
# -------------------------

elif page == "IP Analysis":

    st.header("IP Address Analysis")

    ip_counts = (
        df.groupby("ip_address")
        .size()
        .reset_index(name="event_count")
        .sort_values(
            "event_count",
            ascending=False
        )
    )

    st.subheader("Events by IP Address")

    st.dataframe(
        ip_counts,
        use_container_width=True
    )

    st.subheader("Failed Login Activity by IP")

    failed_by_ip = (
        df[df["event"] == "LOGIN_FAILED"]
        .groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values(
            "failed_attempts",
            ascending=False
        )
    )

    st.bar_chart(
        failed_by_ip.set_index("ip_address")
    )