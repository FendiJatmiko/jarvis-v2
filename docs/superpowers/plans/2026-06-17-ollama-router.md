# Ollama Model Router — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy a FastAPI proxy that routes Ollama queries to qwen2.5:72b (analysis) or qwen2.5-coder:32b (code) automatically, with sticky sessions and persistent user context.

**Architecture:** Single FastAPI app (`router.py`) handles classification via keyword matching + prefix overrides, maintains a JSON-backed session store on a hostPath volume, and streams proxied responses from Ollama. Deployed as a k8s pod on master1 in the `ollama` namespace behind the existing `ollama.nzmweb.com` privreg ingress.

**Tech Stack:** Python 3.11, FastAPI, httpx (async streaming), uvicorn, Docker, Kubernetes

## Global Constraints

- Image registry: `docker-registry.nzmweb.com/ollama-router:latest`
- Ollama internal URL: `http://ollama.ollama.svc.cluster.local:11434`
- k8s namespace: `ollama`
- Target node: `master1` — must include control-plane + etcd tolerations
- Session file path (in pod): `/data/sessions.json`
- hostPath on master1: `/opt/ollama-router`
- Code model: `qwen2.5-coder:32b`
- Analysis model: `qwen2.5:72b`
- Session TTL: 1800 seconds (30 minutes)

---

### Task 1: router.py — classification + session store

**Files:**
- Create: `router/router.py`
- Create: `router/requirements.txt`
- Create: `router/test_router.py`

**Interfaces:**
- Produces: `classify(text: str) -> str` returns `"qwen2.5-coder:32b"` or `"qwen2.5:72b"`
- Produces: `process_message(user_id: str, message: str, sessions: dict) -> tuple[str, str, dict]` returns `(model, context_injection, updated_sessions)`
- Produces: `extract_user_id(auth_header: str, client_ip: str) -> str`

- [ ] **Step 1: Create requirements.txt**

```
fastapi==0.115.0
uvicorn==0.30.0
httpx==0.27.0
```

- [ ] **Step 2: Write failing tests for classification and session logic**

Create `router/test_router.py`:

```python
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
```

- [ ] **Step 3: Run tests — expect all to fail (router.py doesn't exist yet)**

```bash
cd router
pip install -r requirements.txt pytest
pytest test_router.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'router'`

- [ ] **Step 4: Write router.py**

Create `router/router.py`:

```python
import asyncio
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
SESSION_TTL = 1800  # 30 minutes
SESSIONS_FILE = Path(os.getenv("SESSIONS_FILE", "/data/sessions.json"))

CODE_KEYWORDS = {
    "write", "implement", "function", "class", "script", "debug", "fix",
    "refactor", "import", "def", "dockerfile", "bash", "regex", "compile",
    "npm", "pip", "test", "unittest", "pytest", "syntax", "algorithm",
    "code", "program", "snippet", "loop", "array", "parse", "lint",
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
```

- [ ] **Step 5: Run tests — expect all to pass**

```bash
cd router
SESSIONS_FILE=/tmp/test_sessions.json pytest test_router.py -v
```

Expected output:
```
test_router.py::test_classify_code_keywords PASSED
test_router.py::test_classify_implement PASSED
test_router.py::test_classify_debug PASSED
test_router.py::test_classify_analysis_default PASSED
test_router.py::test_classify_pentest PASSED
test_router.py::test_classify_empty PASSED
test_router.py::test_extract_user_id_bearer PASSED
test_router.py::test_extract_user_id_default_bearer PASSED
test_router.py::test_extract_user_id_no_auth PASSED
test_router.py::test_process_new_session_code PASSED
test_router.py::test_process_new_session_analysis PASSED
test_router.py::test_process_active_session_sticks PASSED
test_router.py::test_process_resume_context_injected PASSED
test_router.py::test_process_code_prefix_forces_model PASSED
test_router.py::test_process_analyze_prefix_forces_model PASSED
test_router.py::test_process_reset_prefix_clears_session PASSED
test_router.py::test_process_expired_session_reclassifies PASSED
test_router.py::test_process_topic_truncated_to_120 PASSED
18 passed
```

- [ ] **Step 6: Commit**

```bash
git add router/router.py router/requirements.txt router/test_router.py
git commit -m "feat: add ollama router with classification and session store"
```

---

### Task 2: Dockerfile + build + push to private registry

**Files:**
- Create: `router/Dockerfile`

**Interfaces:**
- Consumes: `router/router.py`, `router/requirements.txt`
- Produces: `docker-registry.nzmweb.com/ollama-router:latest` image in registry

- [ ] **Step 1: Create Dockerfile**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY router.py .
RUN mkdir -p /data
CMD ["uvicorn", "router:app", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 2: Log in to private registry**

```bash
docker login docker-registry.nzmweb.com
```

Enter credentials when prompted.

- [ ] **Step 3: Build the image**

```bash
cd router
docker build -t docker-registry.nzmweb.com/ollama-router:latest .
```

Expected: `Successfully tagged docker-registry.nzmweb.com/ollama-router:latest`

- [ ] **Step 4: Push to registry**

```bash
docker push docker-registry.nzmweb.com/ollama-router:latest
```

Expected: `latest: digest: sha256:...`

- [ ] **Step 5: Verify image is in registry**

```bash
curl -s https://docker-registry.nzmweb.com/v2/ollama-router/tags/list
```

Expected: `{"name":"ollama-router","tags":["latest"]}`

- [ ] **Step 6: Commit**

```bash
git add router/Dockerfile
git commit -m "feat: add ollama-router Dockerfile"
```

---

### Task 3: Kubernetes manifests — deploy and wire up ingress

**Files:**
- Create: `router/k8s-router.yaml`

**Interfaces:**
- Consumes: `docker-registry.nzmweb.com/ollama-router:latest` (from Task 2)
- Produces: `ollama-router` pod running in `ollama` namespace, `ollama.nzmweb.com` routing to router

- [ ] **Step 1: Create k8s-router.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama-router
  namespace: ollama
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ollama-router
  template:
    metadata:
      labels:
        app: ollama-router
    spec:
      nodeSelector:
        kubernetes.io/hostname: master1
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      - key: node-role.kubernetes.io/etcd
        operator: Exists
        effect: NoExecute
      containers:
      - name: router
        image: docker-registry.nzmweb.com/ollama-router:latest
        ports:
        - containerPort: 8080
        env:
        - name: OLLAMA_URL
          value: "http://ollama.ollama.svc.cluster.local:11434"
        - name: SESSIONS_FILE
          value: "/data/sessions.json"
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        volumeMounts:
        - name: sessions
          mountPath: /data
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 3
          periodSeconds: 10
      volumes:
      - name: sessions
        hostPath:
          path: /opt/ollama-router
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: ollama-router
  namespace: ollama
spec:
  selector:
    app: ollama-router
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ollama
  namespace: ollama
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
spec:
  ingressClassName: privreg
  rules:
  - host: ollama.nzmweb.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ollama-router
            port:
              number: 80
```

- [ ] **Step 2: Apply the Deployment and Service first**

```bash
ssh server-IOM "kubectl apply -f -" < router/k8s-router.yaml
```

- [ ] **Step 3: Wait for pod to be ready**

```bash
ssh server-IOM "kubectl rollout status deployment/ollama-router -n ollama"
```

Expected: `deployment "ollama-router" successfully rolled out`

- [ ] **Step 4: Verify pod is running and healthy**

```bash
ssh server-IOM "kubectl get pods -n ollama && kubectl logs -n ollama deploy/ollama-router --tail=10"
```

Expected: pod status `Running`, logs show `Application startup complete.`

- [ ] **Step 5: Verify ingress updated and router is reachable**

```bash
curl -s http://ollama.nzmweb.com/health
```

Expected: `{"status":"ok","sessions":0}`

- [ ] **Step 6: Smoke test classification via the live router**

```bash
# Should route to coder:32b — check via status endpoint
curl -s -X POST http://ollama.nzmweb.com/api/generate \
  -H "Authorization: Bearer fendi" \
  -d '{"prompt":"write a python hello world","stream":false}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('model used:', d.get('model','unknown'))"

curl -s http://ollama.nzmweb.com/router/status | python3 -m json.tool
```

Expected: `"model": "qwen2.5-coder:32b"` in session for `fendi`

- [ ] **Step 7: Commit**

```bash
git add router/k8s-router.yaml
git commit -m "feat: deploy ollama-router to k8s, update ollama.nzmweb.com ingress"
```

---

### Task 4: Update Open Interpreter config

**Files:**
- Modify: `~/.config/open-interpreter/config.yaml`

**Interfaces:**
- Consumes: `ollama.nzmweb.com` (now pointing to router from Task 3)

- [ ] **Step 1: Update config**

Replace `~/.config/open-interpreter/config.yaml` with:

```yaml
model: ollama/qwen2.5:72b
api_base: http://ollama.nzmweb.com
api_key: fendi
context_window: 32000
max_tokens: 4096
safe_mode: ask
```

- [ ] **Step 2: Verify routing works end-to-end from Open Interpreter**

```bash
echo "write a python function that checks if a port is open" | \
  interpreter --model ollama/qwen2.5:72b \
              --api_base http://ollama.nzmweb.com \
              --api_key fendi \
              -y 2>/dev/null | head -20
```

Then immediately check which model was used:

```bash
curl -s http://ollama.nzmweb.com/router/status | python3 -m json.tool
```

Expected: session for `fendi` shows `"model": "qwen2.5-coder:32b"` (code keyword detected).

- [ ] **Step 3: Test session stickiness**

```bash
# Second query — analysis topic — should still use coder:32b (session locked)
curl -s -X POST http://ollama.nzmweb.com/v1/chat/completions \
  -H "Authorization: Bearer fendi" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"explain CVE-2023-6553"}],"stream":false}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['model'])"
```

Expected: `qwen2.5-coder:32b` (still locked from previous code session)

- [ ] **Step 4: Test reset prefix**

```bash
curl -s -X POST http://ollama.nzmweb.com/v1/chat/completions \
  -H "Authorization: Bearer fendi" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"reset: explain CVE-2023-6553"}],"stream":false}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['model'])"
```

Expected: `qwen2.5:72b` (session cleared, re-classified as analysis)

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: update Open Interpreter config to use ollama-router"
```
