import json
import learn

def test_explain_parses_llm_json():
    payload = {"WHAT":"upload bug","WHY":"no check","REQUEST":"POST /x"}
    out = learn.explain("MATCH", "wp-file-manager 6.0", lambda p: json.dumps(payload))
    assert out == payload

def test_explain_blank_on_empty_llm():
    out = learn.explain("MATCH", "ctx", lambda p: "")
    assert set(out.keys()) == {"WHAT","WHY","REQUEST"}
    assert all(v == "(unavailable)" for v in out.values())

def test_explain_never_raises_on_garbage():
    out = learn.explain("EXPLOIT", "ctx", lambda p: "not json at all")
    assert out["WHAT"] == "(unavailable)"

def test_explain_never_raises_when_llm_fn_throws():
    def boom(prompt):
        raise RuntimeError("llm down")
    out = learn.explain("MATCH", "ctx", boom)
    assert set(out.keys()) == {"WHAT","WHY","REQUEST"}
    assert all(v == "(unavailable)" for v in out.values())

def test_explain_no_defense_field():
    payload = {"WHAT":"a","WHY":"b","REQUEST":"c","DEFENSE":"should be ignored"}
    out = learn.explain("MATCH", "ctx", lambda p: json.dumps(payload))
    assert "DEFENSE" not in out
    assert set(out.keys()) == {"WHAT","WHY","REQUEST"}

def test_explain_empty_field_stays_unavailable():
    import json as _json
    out = learn.explain("MATCH", "ctx", lambda p: _json.dumps({"WHAT":"","WHY":"real","REQUEST":""}))
    assert out["WHAT"] == "(unavailable)"
    assert out["WHY"] == "real"
