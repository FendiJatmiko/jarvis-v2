import json
import learn

def test_explain_parses_llm_json():
    facts = {"summary": "wp-file-manager 6.0", "request": "POST /connector.minimal.php"}
    out = learn.explain("MATCH", facts, lambda p: json.dumps({"WHAT": "upload bug", "WHY": "no check"}))
    assert out == {"WHAT": "upload bug", "WHY": "no check", "REQUEST": "POST /connector.minimal.php"}

def test_request_is_verbatim_from_facts_not_llm():
    # even if the LLM tries to supply a REQUEST, the real one from facts wins
    facts = {"summary": "x", "request": "POST /real-endpoint"}
    out = learn.explain("EXPLOIT", facts, lambda p: json.dumps({"WHAT": "a", "WHY": "b", "REQUEST": "GET /fake"}))
    assert out["REQUEST"] == "POST /real-endpoint"

def test_explain_blank_on_empty_llm_keeps_real_request():
    facts = {"summary": "x", "request": "POST /x"}
    out = learn.explain("MATCH", facts, lambda p: "")
    assert set(out.keys()) == {"WHAT", "WHY", "REQUEST"}
    assert out["WHAT"] == "(unavailable)"
    assert out["WHY"] == "(unavailable)"
    assert out["REQUEST"] == "POST /x"     # deterministic, still present

def test_explain_no_request_detection_phase():
    out = learn.explain("FINGERPRINT", {"summary": "wp detected", "request": None}, lambda p: "{}")
    assert out["REQUEST"] == "(no request — detection phase)"

def test_explain_never_raises_on_garbage():
    out = learn.explain("EXPLOIT", {"summary": "x"}, lambda p: "not json at all")
    assert out["WHAT"] == "(unavailable)"

def test_explain_never_raises_when_llm_fn_throws():
    def boom(prompt):
        raise RuntimeError("llm down")
    out = learn.explain("MATCH", {"summary": "x", "request": "POST /x"}, boom)
    assert set(out.keys()) == {"WHAT", "WHY", "REQUEST"}
    assert out["REQUEST"] == "POST /x"

def test_explain_no_defense_field():
    facts = {"summary": "x", "request": "POST /x"}
    out = learn.explain("MATCH", facts, lambda p: json.dumps({"WHAT": "a", "WHY": "b", "DEFENSE": "ignored"}))
    assert "DEFENSE" not in out
    assert set(out.keys()) == {"WHAT", "WHY", "REQUEST"}

def test_cve_is_passed_into_prompt():
    seen = {}
    def capture(prompt):
        seen["p"] = prompt
        return "{}"
    learn.explain("MATCH", {"summary": "s", "cve": "CVE-2020-25213", "detail": "elFinder upload"}, capture)
    assert "CVE-2020-25213" in seen["p"]
    assert "elFinder upload" in seen["p"]
