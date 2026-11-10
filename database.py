import sqlite3
import pandas as pd


DATABASE_NAME = "security_logs.db"


def get_connection():
    return sqlite3.connect(DATABASE_NAME)


def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            username TEXT,
            event TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            alert_type TEXT,
            severity TEXT,
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_events(df):
    connection = get_connection()

    df.to_sql(
        "security_events",
        connection,
        if_exists="replace",
        index=False
    )

    connection.close()


def save_alerts(df):
    connection = get_connection()

    df.to_sql(
        "security_alerts",
        connection,
        if_exists="replace",
        index=False
    )

    connection.close()


def get_events():
    connection = get_connection()

    df = pd.read_sql_query(
        "SELECT * FROM security_events",
        connection
    )

    connection.close()

    return df


def get_alerts():
    connection = get_connection()

    df = pd.read_sql_query(
        "SELECT * FROM security_alerts",
        connection
    )

    connection.close()

    return df