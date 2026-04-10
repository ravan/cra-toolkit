# This app imports requests but only uses its Session object for OPTIONS probes,
# which do not invoke the redirect handling code path where CVE-2023-43804
# lives. The CVE function is not reachable from any entry point.

import requests

def check_server(url):
    session = requests.Session()
    resp = session.options(url)  # OPTIONS does not follow redirects
    return resp.headers

if __name__ == "__main__":
    check_server("https://example.com")
