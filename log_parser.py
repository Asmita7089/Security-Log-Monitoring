import pandas as pd


def parse_logs(file_path):
    records = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split("|")]

            if len(parts) != 4:
                continue

            timestamp, ip_address, username, event = parts

            records.append({
                "timestamp": timestamp,
                "ip_address": ip_address,
                "username": username,
                "event": event
            })

    df = pd.DataFrame(records)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df