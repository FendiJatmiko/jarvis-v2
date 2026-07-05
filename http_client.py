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
        return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kw)

    def post(self, url, **kw):
        return self.session.post(url, timeout=self.timeout, allow_redirects=True, **kw)
