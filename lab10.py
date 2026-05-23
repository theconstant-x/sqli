# Lab 10 — SQL Injection UNION Attack: Retrieving Multiple Values in a Single Column
# PortSwigger: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column
#
# Vulnerability: Product category filter
# Aim:           Retrieve usernames and passwords even when only ONE string column is available.
#                dump_table() in sqli_utils handles this by concatenating columns with ||.
#
# This lab uses the same full enumeration flow as lab5_6.py.
# Imports run() directly instead of spawning a subprocess — cleaner and portable.
#
# Usage: python lab10.py <url>

import sys
import urllib3
from sqli_utils import banner, section
from lab5_6 import run

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == "__main__":
    banner()
    section("LAB 10 — UNION: MULTIPLE VALUES IN SINGLE COLUMN")

    if len(sys.argv) != 2:
        print("  Usage: python lab10.py <url>")
        sys.exit(1)

    run(sys.argv[1].rstrip("/") + "/")
