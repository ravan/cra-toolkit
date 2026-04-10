# Minimal Flask-style application that uses requests to fetch user-supplied URLs.
# The CVE-2023-43804 vulnerability in urllib3 is reachable through requests.get()
# because requests internally constructs a urllib3 PoolManager and calls its
# request() method, which constructs Retry objects that handle redirects.

import requests

def fetch_user_url(url):
    """Fetches a URL provided by an untrusted user."""
    response = requests.get(url, allow_redirects=True)
    return response.text

if __name__ == "__main__":
    fetch_user_url("https://example.com")
