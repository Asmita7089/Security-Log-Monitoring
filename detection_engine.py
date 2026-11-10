import pandas as pd


def detect_suspicious_activity(df, failed_threshold=3):
    alerts = []

    if df.empty:
        return pd.DataFrame()

    failed_logins = df[df["event"] == "LOGIN_FAILED"]

    failed_counts = failed_logins.groupby(
        ["ip_address", "username"]
    ).size().reset_index(name="failed_attempts")

    for _, row in failed_counts.iterrows():

        if row["failed_attempts"] >= failed_threshold:
            alerts.append({
                "ip_address": row["ip_address"],
                "username": row["username"],
                "failed_attempts": row["failed_attempts"],
                "alert_type": "Repeated Failed Login",
                "severity": "High"
            })

    return pd.DataFrame(alerts)


def detect_success_after_failures(df):
    alerts = []

    if df.empty:
        return pd.DataFrame()

    for ip_address in df["ip_address"].unique():

        ip_logs = df[df["ip_address"] == ip_address].sort_values(
            "timestamp"
        )

        failed_count = 0

        for _, row in ip_logs.iterrows():

            if row["event"] == "LOGIN_FAILED":
                failed_count += 1

            elif row["event"] == "LOGIN_SUCCESS" and failed_count >= 3:
                alerts.append({
                    "ip_address": ip_address,
                    "username": row["username"],
                    "failed_attempts_before_success": failed_count,
                    "alert_type": "Successful Login After Multiple Failures",
                    "severity": "High"
                })

                failed_count = 0

    return pd.DataFrame(alerts)