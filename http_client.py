import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    def __init__(self, insecure=True, timeout=15):
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (pentest-agent)"})
        self.timeout = timeout

    def get(self, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        return self.session.get(url, **kw)

    def post(self, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        return self.session.post(url, **kw)
