# proxies.py
# Burp Suite proxy config — imported by all lab scripts.
# Burp must be running on 127.0.0.1:8080 before running any lab.

proxies = {
    "http":  "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
