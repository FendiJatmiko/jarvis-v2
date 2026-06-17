import time
import pytest
from router import classify, process_message, extract_user_id, CODE_MODEL, ANALYSIS_MODEL, SESSION_TTL

# --- classify ---

def test_classify_code_keywords():
    assert classify("write a python function to scan ports") == CODE_MODEL

def test_classify_implement():
    assert classify("implement a rate limiter class") == CODE_MODEL

def test_classify_debug():
    assert classify("debug this script it's broken") == CODE_MODEL

def test_classify_analysis_default():
    assert classify("what is CVE-2023-6553?") == ANALYSIS_MODEL

def test_classify_pentest():
    assert classify("explain how xmlrpc.php is exploited") == ANALYSIS_MODEL

def test_classify_empty():
    assert classify("") == ANALYSIS_MODEL

# --- extract_user_id ---

def test_extract_user_id_bearer():
    assert extract_user_id("Bearer fendi", "1.2.3.4") == "fendi"

def test_extract_user_id_default_bearer():
    # "ollama" and empty bearer fall back to IP hash
    result = extract_user_id("Bearer ollama", "1.2.3.4")
    assert result != "ollama"
    assert len(result) == 8

def test_extract_user_id_no_auth():
    result = extract_user_id("", "1.2.3.4")
    assert len(result) == 8

# --- process_message ---

def test_process_new_session_code():
    sessions = {}
    model, context, sessions = process_message("fendi", "write a bash script", sessions)
    assert model == CODE_MODEL
    assert context == ""
    assert sessions["fendi"]["model"] == CODE_MODEL
    assert sessions["fendi"]["topic"] == "write a bash script"

def test_process_new_session_analysis():
    sessions = {}
    model, context, sessions = process_message("fendi", "explain CVE-2024-1234", sessions)
    assert model == ANALYSIS_MODEL
    assert context == ""

def test_process_active_session_sticks():
    sessions = {"fendi": {"model": CODE_MODEL, "topic": "bash scripting", "last_seen": time.time()}}
    model, context, sessions = process_message("fendi", "explain CVE-2024-1234", sessions)
    assert model == CODE_MODEL  # locked, not re-classified

def test_process_resume_context_injected():
    sessions = {"fendi": {"model": CODE_MODEL, "topic": "FastAPI SSRF testing", "last_seen": time.time()}}
    model, context, sessions = process_message("fendi", "hello", sessions)
    assert "FastAPI SSRF testing" in context
    assert "coder" in context.lower() or "qwen2.5-coder" in context

def test_process_code_prefix_forces_model():
    sessions = {}
    model, context, sessions = process_message("fendi", "code: explain this vulnerability", sessions)
    assert model == CODE_MODEL

def test_process_analyze_prefix_forces_model():
    sessions = {}
    model, context, sessions = process_message("fendi", "analyze: write me a loop", sessions)
    assert model == ANALYSIS_MODEL

def test_process_reset_prefix_clears_session():
    sessions = {"fendi": {"model": CODE_MODEL, "topic": "old topic", "last_seen": time.time()}}
    model, context, sessions = process_message("fendi", "reset: explain CVE-2024-1234", sessions)
    assert model == ANALYSIS_MODEL  # re-classified, not locked to old model
    assert context == ""
    assert sessions["fendi"]["topic"] == "explain CVE-2024-1234"

def test_process_expired_session_reclassifies():
    old_time = time.time() - SESSION_TTL - 1
    sessions = {"fendi": {"model": CODE_MODEL, "topic": "old topic", "last_seen": old_time}}
    model, context, sessions = process_message("fendi", "explain CVE-2024-1234", sessions)
    assert model == ANALYSIS_MODEL  # expired, re-classified
    assert context == ""

def test_process_topic_truncated_to_120():
    sessions = {}
    long_msg = "x" * 200
    model, context, sessions = process_message("fendi", long_msg, sessions)
    assert len(sessions["fendi"]["topic"]) == 120
