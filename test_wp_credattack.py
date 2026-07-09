from unittest.mock import MagicMock
import wp_credattack


def test_finds_working_credential():
    # login_fn returns True only for ("admin","password")
    def fake_login(base, http, u, pw):
        return (u, pw) == ("admin", "password")
    out = wp_credattack.try_credentials("http://t", MagicMock(), login_fn=fake_login)
    assert out["username"] == "admin" and out["password"] == "password"
    assert out["attempts"] >= 1

def test_returns_none_when_nothing_works():
    out = wp_credattack.try_credentials("http://t", MagicMock(),
                                        login_fn=lambda *a: False)
    assert out is None

def test_respects_attempt_cap():
    calls = []
    def fake_login(base, http, u, pw):
        calls.append((u, pw)); return False
    wp_credattack.try_credentials("http://t", MagicMock(), login_fn=fake_login, cap=5)
    assert len(calls) == 5          # stopped at the cap, didn't try the whole list

def test_extra_pairs_tried_first():
    order = []
    def fake_login(base, http, u, pw):
        order.append((u, pw)); return (u, pw) == ("bob", "s3cret")
    out = wp_credattack.try_credentials("http://t", MagicMock(),
                                        extra_pairs=[("bob", "s3cret")], login_fn=fake_login)
    assert out["username"] == "bob"
    assert order[0] == ("bob", "s3cret")   # explicit pair attempted before the built-ins

def test_load_wordlist_splits_passwords_and_pairs(tmp_path):
    p = tmp_path / "wl.txt"
    p.write_text("# comment\n\nhunter2\nadmin:letmein\nqwerty\n")
    passwords, pairs = wp_credattack.load_wordlist(str(p))
    assert passwords == ["hunter2", "qwerty"]
    assert pairs == [("admin", "letmein")]

def test_load_wordlist_missing_file_is_empty():
    assert wp_credattack.load_wordlist("/no/such/file") == ([], [])
