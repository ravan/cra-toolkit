# This app uses requests only for URL preparation (not sending).
# PreparedRequest.prepare() parses and normalises the URL using Python's
# stdlib urllib.parse — it does not open a connection or invoke urllib3.
# CVE-2023-43804 (urllib3 cookie leakage via redirect) is not reachable.

import requests


def validate_url(url):
    """Validates a URL by preparing — but not sending — a GET request."""
    req = requests.Request('GET', url)
    prepared = req.prepare()
    return prepared.url


if __name__ == "__main__":
    validate_url("https://example.com")
