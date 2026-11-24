import re
import json
from . import recipes as wp_recipes


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


def _synthesize(plugin, ragflow_fn, llm_fn):
    ctx = ragflow_fn(
        f"unauthenticated arbitrary file upload or RCE in {plugin['slug']} "
        f"{plugin['version']}, exploit request details"
    )
    if not ctx:
        return None
    if not llm_fn:
        return None
    prompt = (
        f"Given this CVE context: {ctx}\n"
        f"Produce ONLY a JSON object for an unauthenticated file-upload exploit of "
        f"{plugin['slug']} {plugin['version']} with keys: plugin, cve, affected, method, "
        f"endpoint, params, field, upload_path (must contain '{{filename}}'), note."
    )
    raw = llm_fn(prompt)
    try:
        obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return None
    obj["source"] = "llm"
    return obj


def match(wp_info, ragflow_fn=None, llm_fn=None):
    candidates = []
    for p in wp_info.get("plugins", []):
        recs = wp_recipes.find_recipes(p["slug"])
        matched = [r for r in recs if version_satisfies(p["version"], r["affected"])]
        if matched:
            candidates.extend(matched)
        elif ragflow_fn:
            synth = _synthesize(p, ragflow_fn, llm_fn)
            if synth:
                candidates.append(synth)
    candidates.sort(key=lambda c: 0 if c.get("source") == "registry" else 1)
    return candidates
