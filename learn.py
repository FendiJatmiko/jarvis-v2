import json

FIELDS = ["WHAT", "WHY", "REQUEST", "DEFENSE"]


def explain(phase, context, llm_fn):
    prompt = (
        f"Explain this pentest step for a learner. Phase: {phase}. Context: {context}. "
        f"Return ONLY a JSON object with keys WHAT, WHY, REQUEST, DEFENSE. "
        f"WHAT=vulnerability class in one line; WHY=the specific missing check; "
        f"REQUEST=the exact HTTP request; DEFENSE=the concrete fix."
    )
    data = {f: "(unavailable)" for f in FIELDS}
    try:
        raw = llm_fn(prompt) or ""
        obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
        for f in FIELDS:
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
