import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Matches JS cookie-challenge stubs like:
#   document.cookie = "humans_ofp=1; path=/"; document.location.reload(true);
_CHALLENGE_COOKIE = re.compile(r"""document\.cookie\s*=\s*["']([^"'=]+)=([^"';]+)""", re.I)


class HttpClient:
    def __init__(self, insecure=True, timeout=15, solve_challenges=True):
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (pentest-agent)"})
        self.timeout = timeout
        self.solve_challenges = solve_challenges

    # ── JS cookie-challenge handling (what a real browser/attacker does) ──────
    def _is_challenge(self, resp):
        """A tiny page whose only job is to set a cookie via JS and reload —
        the anti-bot stub. Real content is far larger and doesn't self-reload."""
        body = getattr(resp, "text", "")
        if not isinstance(body, str):
            return False
        return "document.cookie" in body and "reload" in body and len(body) < 2000

    def _solve(self, resp):
        """Extract the cookie the challenge wants set, plant it on the session.
        Returns True if a cookie was solved."""
        m = _CHALLENGE_COOKIE.search(getattr(resp, "text", "") or "")
        if not m:
            return False
        self.session.cookies.set(m.group(1), m.group(2))
        return True

    def _request(self, method, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        fn = self.session.get if method == "GET" else self.session.post
        resp = fn(url, **kw)
        # If we hit a cookie challenge, solve it once and replay — after this the
        # cookie rides on the session, so every later request sails through.
        if self.solve_challenges and self._is_challenge(resp) and self._solve(resp):
            resp = fn(url, **kw)
        return resp

    def get(self, url, **kw):
        return self._request("GET", url, **kw)

    def post(self, url, **kw):
        return self._request("POST", url, **kw)
