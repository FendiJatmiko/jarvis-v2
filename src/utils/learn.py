import json

FIELDS = ["WHAT", "WHY", "REQUEST"]


def explain(phase, facts, llm_fn):
    """Render a WHAT/WHY/REQUEST learning box for one real finding.

    facts: dict describing what the tool ACTUALLY found/did this phase:
      - summary: one-line human summary (required)
      - cve:     the real CVE id, or None
      - detail:  the real technical detail (e.g. the recipe note)
      - request: the ACTUAL request string the tool built, or None

    REQUEST is taken verbatim from facts — never invented by the LLM.
    WHAT/WHY are asked from the LLM but strictly grounded in `facts`, so the
    model describes the real finding instead of hallucinating a different bug.
    """
    request = facts.get("request") or "(no request — detection phase)"
    data = {"WHAT": "(unavailable)", "WHY": "(unavailable)", "REQUEST": request}

    cve = facts.get("cve") or "no specific CVE"
    detail = facts.get("detail") or facts.get("summary") or ""
    prompt = (
        "You are explaining ONE specific, already-identified finding to a learner. "
        "Do NOT invent, guess, or generalise to a different vulnerability — describe "
        "only the finding given below.\n"
        f"Phase: {phase}\n"
        f"Finding: {facts.get('summary', '')}\n"
        f"CVE: {cve}\n"
        f"Technical detail: {detail}\n"
        "Return ONLY a JSON object with keys WHAT and WHY, one short line each. "
        "WHAT = what this specific issue is (name the real vulnerability class). "
        "WHY = the specific missing check or behaviour that makes it work."
    )
    try:
        raw = llm_fn(prompt) or ""
        obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
        for f in ("WHAT", "WHY"):
            if obj.get(f):
                data[f] = str(obj[f])
    except Exception:
        pass

    try:
        _render(phase, data)
    except Exception:
        pass
    return data


def _render(phase, data):
    print(f"\n┌─ [{phase}]")
    for f in FIELDS:
        print(f"│  {f:<8} {data[f]}")
    print("└─")
