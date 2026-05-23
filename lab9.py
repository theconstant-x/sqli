# Lab 09 — SQL Injection UNION Attack: Retrieving Data from Other Tables
# PortSwigger: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables
#
# Vulnerability: Product category filter
# Aim:           Retrieve usernames and passwords from the users table, log in as administrator
#
# This lab uses the same full enumeration flow as lab5_6.py.
# Imports run() directly instead of spawning a subprocess — cleaner and portable.
#
# Usage: python lab9.py <url>

import sys
import urllib3
from sqli_utils import banner, section
from lab5_6 import run

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == "__main__":
    banner()
    section("LAB 09 — UNION: RETRIEVE DATA FROM OTHER TABLES")

    if len(sys.argv) != 2:
        print("  Usage: python lab9.py <url>")
        sys.exit(1)

    run(sys.argv[1].rstrip("/") + "/")
