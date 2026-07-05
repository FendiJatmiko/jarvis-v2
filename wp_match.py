import re


def _ver_tuple(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(x) for x in parts) or (0,)


def _cmp(a, b):
    la, lb = list(a), list(b)
    while len(la) < len(lb):
        la.append(0)
    while len(lb) < len(la):
        lb.append(0)
    return (la > lb) - (la < lb)


def version_satisfies(version, constraint):
    v = _ver_tuple(version)
    for part in constraint.split(","):
        part = part.strip()
        m = re.match(r"^(<=|>=|<|>|==)?\s*([\d.]+)$", part)
        if not m:
            return False
        op = m.group(1) or "=="
        r = _cmp(v, _ver_tuple(m.group(2)))
        ok = {"<=": r <= 0, ">=": r >= 0, "<": r < 0, ">": r > 0, "==": r == 0}[op]
        if not ok:
            return False
    return True
