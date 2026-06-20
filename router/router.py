import hashlib
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama.ollama.svc.cluster.local:11434")
CODE_MODEL = "qwen2.5-coder:32b"
ANALYSIS_MODEL = "qwen2.5:72b"
FAST_MODEL = "qwen2.5:7b"
SESSION_TTL = 1800  # 30 minutes
SESSIONS_FILE = Path(os.getenv("SESSIONS_FILE", "/data/sessions.json"))

CODE_KEYWORDS = {
    "write", "implement", "function", "class", "script", "debug", "fix",
    "refactor", "import", "def", "dockerfile", "bash", "regex", "compile",
    "npm", "pip", "test", "unittest", "pytest", "syntax", "algorithm",
}

_sessions: dict = {}


def classify(text: str) -> str:
    words = set(text.lower().split())
    if words & CODE_KEYWORDS:
        return CODE_MODEL
    return ANALYSIS_MODEL


def extract_user_id(auth_header: str, client_ip: str) -> str:
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token and token not in ("ollama", ""):
            return token
    return hashlib.md5(client_ip.encode()).hexdigest()[:8]


def process_message(user_id: str, message: str, sessions: dict) -> tuple[str, str, dict]:
    """Returns (model, context_injection, updated_sessions)."""
    now = time.time()

    # Expire old sessions
    sessions = {
        uid: s for uid, s in sessions.items()
        if now - s["last_seen"] < SESSION_TTL
    }

    # Handle prefixes — strip before processing
    reset = False
    forced_model = None

    if message.startswith("reset:"):
        message = message[6:].strip()
        reset = True
        sessions.pop(user_id, None)
    elif message.startswith("code:"):
        message = message[5:].strip()
        forced_model = CODE_MODEL
    elif message.startswith("analyze:"):
        message = message[8:].strip()
        forced_model = ANALYSIS_MODEL

    session = sessions.get(user_id)
    context = ""

    if session and not reset:
        # Active session: use locked model (or override if prefix given)
        model = forced_model or session["model"]
        if forced_model:
            session["model"] = forced_model
        session["last_seen"] = now
        short_name = model.split(":")[0].split("/")[-1]
        context = f'[Resuming: previously working on "{session["topic"]}", model: {short_name}]'
    else:
        # New or reset session
        model = forced_model or classify(message)
        topic = message[:120]
        sessions[user_id] = {"model": model, "topic": topic, "last_seen": now}

    return model, context, sessions


def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_sessions(sessions: dict) -> None:
    try:
        SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))
    except Exception:
        pass


def _get_last_user_message(messages: list) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        return part.get("text", "")
            return str(content)
    return ""


def _inject_context(messages: list, context: str) -> list:
    if not context:
        return messages
    if messages and messages[0].get("role") == "system":
        messages[0]["content"] = context + "\n" + messages[0]["content"]
    else:
        messages.insert(0, {"role": "system", "content": context})
    return messages


@asynccontextmanager
async def lifespan(app: FastAPI):
    _sessions.update(_load_sessions())
    yield


app = FastAPI(lifespan=lifespan)


@app.post("/api/generate")
@app.post("/api/chat")
async def ollama_proxy(request: Request):
    body = await request.json()
    user_id = extract_user_id(
        request.headers.get("Authorization", ""),
        request.client.host if request.client else "unknown",
    )

    if "messages" in body:
        message = _get_last_user_message(body["messages"])
    else:
        message = body.get("prompt", "")

    model, context, updated = process_message(user_id, message, dict(_sessions))
    _sessions.clear()
    _sessions.update(updated)
    _save_sessions(_sessions)

    body["model"] = model

    if context and "messages" in body:
        body["messages"] = _inject_context(body["messages"], context)
    elif context and "system" in body:
        body["system"] = context + "\n" + body.get("system", "")

    endpoint = "/api/chat" if "messages" in body else "/api/generate"
    stream = body.get("stream", True)

    if stream:
        async def _stream():
            async with httpx.AsyncClient(timeout=300) as client:
                async with client.stream("POST", f"{OLLAMA_URL}{endpoint}", json=body) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

        return StreamingResponse(_stream(), media_type="application/x-ndjson")

    async with httpx.AsyncClient(timeout=300) as client:
        resp = await client.post(f"{OLLAMA_URL}{endpoint}", json=body)
        return Response(content=resp.content, media_type="application/json")


@app.post("/v1/chat/completions")
async def openai_proxy(request: Request):
    body = await request.json()
    user_id = extract_user_id(
        request.headers.get("Authorization", ""),
        request.client.host if request.client else "unknown",
    )

    message = _get_last_user_message(body.get("messages", []))
    requested = body.get("model", "")
    known_models = {CODE_MODEL, ANALYSIS_MODEL, FAST_MODEL}
    if requested in known_models:
        # Client explicitly chose a model — bypass routing, preserve session
        model = requested
        context = ""
    else:
        model, context, updated = process_message(user_id, message, dict(_sessions))
        _sessions.clear()
        _sessions.update(updated)
        _save_sessions(_sessions)

    messages = _inject_context(list(body.get("messages", [])), context)

    ollama_payload = {
        "model": model,
        "messages": messages,
        "stream": body.get("stream", True),
        "options": {},
    }
    if "temperature" in body:
        ollama_payload["options"]["temperature"] = body["temperature"]
    if "max_tokens" in body:
        ollama_payload["options"]["num_predict"] = body["max_tokens"]

    if ollama_payload["stream"]:
        async def _openai_stream():
            async with httpx.AsyncClient(timeout=300) as client:
                async with client.stream("POST", f"{OLLAMA_URL}/api/chat", json=ollama_payload) as resp:
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except Exception:
                            continue
                        content = chunk.get("message", {}).get("content", "")
                        done = chunk.get("done", False)
                        sse = {
                            "id": "chatcmpl-router",
                            "object": "chat.completion.chunk",
                            "choices": [{"delta": {"content": content}, "finish_reason": "stop" if done else None}],
                        }
                        yield f"data: {json.dumps(sse)}\n\n"
                        if done:
                            yield "data: [DONE]\n\n"

        return StreamingResponse(_openai_stream(), media_type="text/event-stream")

    async with httpx.AsyncClient(timeout=300) as client:
        resp = await client.post(f"{OLLAMA_URL}/api/chat", json=ollama_payload)
        data = resp.json()
        content = data.get("message", {}).get("content", "")
        return {
            "id": "chatcmpl-router",
            "object": "chat.completion",
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        }


@app.get("/api/tags")
@app.get("/v1/models")
async def list_models():
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{OLLAMA_URL}/api/tags")
        return Response(content=resp.content, media_type="application/json")


@app.get("/health")
async def health():
    return {"status": "ok", "sessions": len(_sessions)}


@app.get("/router/status")
async def router_status():
    now = time.time()
    return {
        "active_sessions": len(_sessions),
        "sessions": {
            uid: {
                "model": s["model"],
                "topic": s["topic"][:60],
                "age_minutes": round((now - s["last_seen"]) / 60, 1),
            }
            for uid, s in _sessions.items()
        },
    }
