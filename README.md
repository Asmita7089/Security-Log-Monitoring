# Security Log Monitoring & Suspicious Activity Detection

A Python-based security monitoring application that parses authentication logs, stores security events, detects suspicious login patterns, and presents security alerts through a Streamlit dashboard.

## Features

- Authentication log parsing
- Successful and failed login monitoring
- Repeated failed login detection
- Detection of successful logins following multiple failures
- IP address activity analysis
- Security alert generation
- SQLite-based event and alert storage
- Interactive Streamlit dashboard

## Detection Rules

### Repeated Failed Login

The system generates a High severity alert when an IP address and username combination records three or more failed login attempts.

### Successful Login After Multiple Failures

The system identifies a successful login occurring after multiple failed login attempts from the same IP address.

## Technology Stack

- Python
- Pandas
- SQLite
- Streamlit

## Project Structure

```text
Security-Log-Monitoring/
│
├── app.py
├── log_parser.py
├── detection_engine.py
├── database.py
├── sample_logs.txt
├── requirements.txt
├── README.md
└── .gitignore