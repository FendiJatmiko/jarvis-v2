# Ollama Model Router — Design Spec
Date: 2026-06-17

## Problem

Ollama on server-IOM hosts two models for different purposes:
- `qwen2.5:72b` — general reasoning, CVE analysis, pentest planning
- `qwen2.5-coder:32b` — code generation, script writing, debugging

Clients (Open Interpreter, future tools) must currently specify the model manually. The goal is a transparent proxy that automatically routes queries to the right model and remembers context across sessions.

---

## Architecture

```
ollama.nzmweb.com (privreg ingress)
        │
        ▼
  ollama-router pod  (ollama namespace, master1)
  ├── POST /v1/chat/completions   ← Open Interpreter (OpenAI-compat)
  ├── POST /api/chat              ← Ollama-native clients
  ├── POST /api/generate          ← Ollama-native clients
  ├── GET  /api/tags              ← passthrough to Ollama
  └── GET  /health
        │
        ├── 1. extract user message + user_id
        ├── 2. check for prefix override
        ├── 3. load session from store
        ├── 4. classify if no active session
        ├── 5. inject resume context into system prompt
        └── 6. stream proxy → ollama.ollama.svc.cluster.local:11434
```

---

## Components

| File | Purpose |
|---|---|
| `router/router.py` | FastAPI app — all logic |
| `router/Dockerfile` | `python:3.11-slim`, deps: fastapi uvicorn httpx |
| `router/k8s-router.yaml` | Deployment + Service + Ingress |

---

## Classification

### Prefix overrides (checked first)
| Prefix | Action |
|---|---|
| `code: <message>` | Force `qwen2.5-coder:32b`, lock session |
| `analyze: <message>` | Force `qwen2.5:72b`, lock session |
| `reset: <message>` | Clear session (model + topic), re-classify message |

### Keyword classifier (fallback)
Code signals → `qwen2.5-coder:32b`:
`write, implement, function, class, script, debug, fix, refactor, import, def, dockerfile, bash, regex, compile, npm, pip, test, unittest, pytest, syntax, algorithm`

Default → `qwen2.5:72b`:
Everything else — CVE, explain, analyze, vulnerability, pentest, why, how does, assess, review, describe, exploit, attack

---

## Session Store

**Data structure** (persisted to `/data/sessions.json`):
```json
{
  "fendi": {
    "model": "qwen2.5-coder:32b",
    "topic": "FastAPI SSRF vulnerability testing on EKS",
    "last_seen": 1781682250
  }
}
```

**User identity:** value of the `Authorization: Bearer <user_id>` header.
- Open Interpreter: set `api_key: fendi` in config
- Fallback: client IP address (if no bearer token)

**Session lifecycle:**
- Created: first message from a user
- Topic: first 120 chars of the first message (updated on `reset:`)
- Expires: 30 minutes of inactivity (last_seen TTL)
- Persisted: written to JSON file on every update

**Persistence:** hostPath volume at `/opt/ollama-router/` on master1. Survives pod restarts. No Redis needed.

**Context injection:** on session resume, prepend to system prompt:
```
[Resuming: previously working on "{topic}", model: {model_shortname}]
```

---

## Streaming

- `httpx.AsyncClient` with `stream=True`
- Bytes passed through directly — no buffering, no transformation
- OpenAI `/v1/chat/completions` → translated to Ollama `/api/chat` format before forwarding, response translated back
- Ollama `/api/chat` and `/api/generate` → forwarded as-is

---

## Kubernetes Deployment

```
Namespace:    ollama
Node:         master1 (nodeSelector + tolerations — same as Ollama pod)
Image:        docker-registry.nzmweb.com/ollama-router:latest
Resources:    requests: 50m CPU / 64Mi RAM  |  limits: 200m CPU / 256Mi RAM
Volume:       hostPath /opt/ollama-router → /data (sessions.json)
Service:      ClusterIP :8080
Ingress:      privreg class, host: ollama.nzmweb.com (replaces current Ollama ingress)
```

Current `ollama.nzmweb.com` ingress is updated to point to `ollama-router` service instead of `ollama` service.

---

## Open Interpreter Config Update

```yaml
# ~/.config/open-interpreter/config.yaml
model: ollama/qwen2.5:72b   # hint only — router overrides this
api_base: http://ollama.nzmweb.com
api_key: fendi               # used as user_id by router
context_window: 32000
max_tokens: 4096
safe_mode: ask
```

The `model` field in the config becomes a fallback hint only — the router always resolves the actual model.

---

## What Changes for the User

| Before | After |
|---|---|
| Must specify model manually | Automatic routing |
| Model swap = manual config edit | Transparent, instant |
| New session = no context | `[Resuming: ...]` injected automatically |
| Session lost on pod restart | Sessions persisted to disk |

---

## Out of Scope

- LLM-based classification (can be added later as option 3)
- Multi-user auth (bearer token is identity only, no secret validation)
- Conversation history storage (Option B — deferred)
- Rate limiting
