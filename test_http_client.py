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
