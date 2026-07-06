from unittest.mock import MagicMock
import http_client

def test_get_passes_timeout_and_redirects():
    c = http_client.HttpClient(timeout=9)
    c.session = MagicMock()
    c.get("http://x/a", params={"p": 1})
    c.session.get.assert_called_once()
    _, kwargs = c.session.get.call_args
    assert kwargs["timeout"] == 9
    assert kwargs["allow_redirects"] is True
    assert kwargs["params"] == {"p": 1}

def test_post_passes_timeout_and_redirects():
    c = http_client.HttpClient(timeout=9)
    c.session = MagicMock()
    c.post("http://x/a", files={"f": ("n", b"d")})
    c.session.post.assert_called_once()
    _, kwargs = c.session.post.call_args
    assert kwargs["timeout"] == 9
    assert kwargs["allow_redirects"] is True

def test_insecure_disables_verify():
    c = http_client.HttpClient(insecure=True)
    assert c.session.verify is False

def test_caller_can_override_timeout_and_redirects():
    c = http_client.HttpClient(timeout=15)
    c.session = MagicMock()
    c.get("http://x/a", timeout=3, allow_redirects=False)
    _, kwargs = c.session.get.call_args
    assert kwargs["timeout"] == 3
    assert kwargs["allow_redirects"] is False


CHALLENGE = ('<html><body><script>document.cookie="humans_ofp=1; path=/"; '
             'document.location.reload(true);</script></body></html>')

def _resp(text, status=200):
    r = MagicMock(); r.text = text; r.status_code = status; return r

def test_solves_cookie_challenge_and_replays():
    c = http_client.HttpClient()
    c.session = MagicMock()
    c.session.get.side_effect = [_resp(CHALLENGE, 409), _resp("<html>real store</html>", 200)]
    r = c.get("http://x/")
    assert r.status_code == 200 and "real store" in r.text
    c.session.cookies.set.assert_called_once_with("humans_ofp", "1")
    assert c.session.get.call_count == 2          # solved, then replayed

def test_challenge_solving_works_for_post_too():
    c = http_client.HttpClient()
    c.session = MagicMock()
    c.session.post.side_effect = [_resp(CHALLENGE, 409), _resp("ok", 200)]
    r = c.post("http://x/upload")
    assert r.text == "ok"
    assert c.session.post.call_count == 2

def test_real_page_is_not_treated_as_challenge():
    c = http_client.HttpClient()
    c.session = MagicMock()
    big = "<html>" + "x" * 3000 + "</html>"      # real pages are large, no reload stub
    c.session.get.return_value = _resp(big, 200)
    r = c.get("http://x/")
    assert c.session.get.call_count == 1          # no replay
    assert r.text == big

def test_challenge_solving_can_be_disabled():
    c = http_client.HttpClient(solve_challenges=False)
    c.session = MagicMock()
    c.session.get.return_value = _resp(CHALLENGE, 409)
    r = c.get("http://x/")
    assert r.status_code == 409
    assert c.session.get.call_count == 1          # left blocked on purpose
