#!/usr/bin/env python3
"""
setup_ragflow.py — rebuild RAGFlow knowledge base + chat assistant from scratch

Steps:
  1. Create CVE+ExploitDB dataset
  2. Download HIGH+CRITICAL CVEs from NVD 2.0 API (paginated) and upload
  3. Download ExploitDB CSV and upload
  4. Create nzmweb-pentest chat assistant
  5. Print updated config values for pentest-agent.py

Usage:
  python3 setup_ragflow.py
"""

import csv
import io
import json
import subprocess
import sys
import time

import requests

RAGFLOW_URL  = "https://rag3.nzmweb.com"
RAGFLOW_KEY  = "ragflow-BjMzg4ZWVlNmNhMjExZjFiOTYyYmUzZj"
OLLAMA_EMBED = "nomic-embed-text"
OLLAMA_CHAT  = "qwen2.5:7b"

RF_HEADERS = {
    "Authorization": f"Bearer {RAGFLOW_KEY}",
    "Content-Type": "application/json",
}

NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PER_PAGE   = 200  # 200 results ≈ 1.5MB per page — fits within network limits
NVD_SLEEP      = 7    # seconds between pages (rate limit: 5 req/30 s without API key)
# CRITICAL only: 30k CVEs, ~150 pages, ~18 min — HIGH (75k) can be added later
NVD_SEVERITIES = ["CRITICAL"]

EXPLOITDB_CSV  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

CVE_CHUNK_SIZE  = 500   # CVEs per uploaded text file
EXDB_CHUNK_SIZE = 1000  # ExploitDB rows per uploaded text file


# ---------------------------------------------------------------------------
# RAGFlow API helpers
# ---------------------------------------------------------------------------

def _rf_get(path: str) -> dict:
    r = requests.get(f"{RAGFLOW_URL}{path}", headers=RF_HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()


def _rf_post(path: str, payload: dict) -> dict:
    r = requests.post(f"{RAGFLOW_URL}{path}", headers=RF_HEADERS, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()


def _upload_document(dataset_id: str, filename: str, content: str) -> str:
    """Multipart upload of a text file; returns document id."""
    r = requests.post(
        f"{RAGFLOW_URL}/api/v1/datasets/{dataset_id}/documents",
        headers={"Authorization": f"Bearer {RAGFLOW_KEY}"},
        files={"file": (filename, content.encode("utf-8"), "text/plain")},
        timeout=120,
    )
    r.raise_for_status()
    resp = r.json()
    if resp.get("code") != 0:
        raise RuntimeError(f"Upload failed: {resp}")
    docs = resp.get("data", [])
    return docs[0]["id"] if docs else ""


def _parse_docs(dataset_id: str, doc_ids: list) -> None:
    """Trigger chunking/embedding for a batch of documents."""
    _rf_post(f"/api/v1/datasets/{dataset_id}/chunks", {"document_ids": doc_ids})


# ---------------------------------------------------------------------------
# Step 1 — Create dataset
# ---------------------------------------------------------------------------

def create_dataset(name: str) -> str:
    # Reuse existing dataset if name already taken
    existing = _rf_get("/api/v1/datasets")
    for ds in existing.get("data", []):
        if ds["name"] == name:
            print(f"  Reusing existing dataset '{name}': {ds['id']}")
            return ds["id"]
    print(f"  Creating dataset '{name}'...")
    resp = _rf_post("/api/v1/datasets", {"name": name, "chunk_method": "naive"})
    if resp.get("code") != 0:
        raise RuntimeError(f"Dataset creation failed: {resp}")
    did = resp["data"]["id"]
    print(f"  Dataset created: {did}")
    return did


# ---------------------------------------------------------------------------
# Step 2 — NVD 2.0 API (HIGH + CRITICAL only)
# ---------------------------------------------------------------------------

def _format_cve(vuln: dict) -> str:
    cve       = vuln.get("cve", {})
    cve_id    = cve.get("id", "")
    published = cve.get("published", "")[:10]
    descs     = cve.get("descriptions", [])
    desc      = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:800]
    metrics   = cve.get("metrics", {})
    cvss_score, severity = "", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m          = metrics[key][0].get("cvssData", {})
            cvss_score = str(m.get("baseScore", ""))
            severity   = m.get("baseSeverity", "") or metrics[key][0].get("baseSeverity", "")
            break
    refs     = cve.get("references", [])
    ref_urls = " | ".join(r.get("url", "") for r in refs[:3])
    return (
        f"CVE: {cve_id}\n"
        f"Published: {published}\n"
        f"CVSS: {cvss_score} ({severity})\n"
        f"Description: {desc}\n"
        f"References: {ref_urls}\n"
    )


def _fetch_nvd_page(severity: str, start_index: int) -> dict:
    url = (
        f"{NVD_API}?cvssV3Severity={severity}"
        f"&startIndex={start_index}&resultsPerPage={NVD_PER_PAGE}"
    )
    for attempt in range(3):
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "--max-time", "180", "--compressed",
                    "-H", "User-Agent: pentest-agent/1.0", url,
                ],
                capture_output=True, text=True, timeout=190,
            )
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError(
                    f"curl rc={result.returncode} stdout={result.stdout[:100]!r} "
                    f"stderr={result.stderr[:200]!r}"
                )
            return json.loads(result.stdout)
        except Exception as e:
            wait = 15 * (attempt + 1)
            print(f"\n  [!] NVD error ({e}) — retry in {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"NVD fetch failed after 3 attempts at index {start_index}")


def upload_nvd(dataset_id: str) -> int:
    total_uploaded = 0

    for severity in NVD_SEVERITIES:
        print(f"\n  Fetching {severity} CVEs from NVD...")
        start_index   = 0
        total_results = None
        page          = 0
        buf: list     = []
        batch_ids: list = []

        while True:
            data = _fetch_nvd_page(severity, start_index)

            if total_results is None:
                total_results = data.get("totalResults", 0)
                pages_needed  = (total_results + NVD_PER_PAGE - 1) // NVD_PER_PAGE
                print(f"  {severity}: {total_results} CVEs (~{pages_needed} pages)")

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                buf.append(_format_cve(v))
                if len(buf) >= CVE_CHUNK_SIZE:
                    fname  = f"nvd_{severity.lower()}_{total_uploaded // CVE_CHUNK_SIZE + 1}.txt"
                    doc_id = _upload_document(dataset_id, fname, "\n---\n".join(buf))
                    if doc_id:
                        batch_ids.append(doc_id)
                    total_uploaded += len(buf)
                    buf = []
                    if len(batch_ids) >= 20:
                        _parse_docs(dataset_id, batch_ids)
                        batch_ids = []

            page        += 1
            start_index += len(vulns)
            pct = start_index / total_results * 100 if total_results else 0
            sys.stdout.write(
                f"\r  [{severity}] page {page}: {start_index}/{total_results} ({pct:.0f}%)"
                f"  {total_uploaded} CVEs uploaded   "
            )
            sys.stdout.flush()

            if start_index >= total_results:
                break
            time.sleep(NVD_SLEEP)

        # flush tail
        if buf:
            fname  = f"nvd_{severity.lower()}_{total_uploaded // CVE_CHUNK_SIZE + 1}.txt"
            doc_id = _upload_document(dataset_id, fname, "\n---\n".join(buf))
            if doc_id:
                batch_ids.append(doc_id)
            total_uploaded += len(buf)
        if batch_ids:
            _parse_docs(dataset_id, batch_ids)

        print(f"\n  {severity} done.")

    print(f"\n  NVD upload complete: {total_uploaded} CVEs (HIGH + CRITICAL)")
    return total_uploaded


# ---------------------------------------------------------------------------
# Step 3 — ExploitDB
# ---------------------------------------------------------------------------

def upload_exploitdb(dataset_id: str) -> int:
    # Columns: id,file,description,date_published,author,type,platform,port,
    #          date_added,date_updated,verified,codes,tags,...
    print("  Downloading ExploitDB CSV...", end=" ", flush=True)
    r = requests.get(
        EXPLOITDB_CSV,
        headers={"User-Agent": "pentest-agent/1.0"},
        timeout=90,
    )
    r.raise_for_status()
    reader = csv.DictReader(io.StringIO(r.text))
    print(f"{r.text.count(chr(10))} entries")

    chunks, buf, n = [], [], 0
    for row in reader:
        eid   = row.get("id", "").strip()
        title = row.get("description", "").strip()
        date  = row.get("date_published", "").strip()
        etype = row.get("type", "").strip()
        plat  = row.get("platform", "").strip()
        codes = row.get("codes", "").strip()
        if not eid:
            continue
        entry = (
            f"ExploitDB ID: {eid}\n"
            f"Title: {title}\n"
            f"Date: {date} | Type: {etype} | Platform: {plat}\n"
            f"CVE refs: {codes}\n"
        )
        buf.append(entry)
        n += 1
        if n % EXDB_CHUNK_SIZE == 0:
            chunks.append("\n---\n".join(buf))
            buf = []
    if buf:
        chunks.append("\n---\n".join(buf))

    doc_ids = []
    for i, chunk in enumerate(chunks):
        fname  = f"exploitdb_part{i+1}.txt"
        doc_id = _upload_document(dataset_id, fname, chunk)
        if doc_id:
            doc_ids.append(doc_id)
        sys.stdout.write(f"\r  Uploaded {i+1}/{len(chunks)} ExploitDB parts   ")
        sys.stdout.flush()
    print()
    if doc_ids:
        _parse_docs(dataset_id, doc_ids)
    print(f"  ExploitDB upload complete: {n} entries in {len(chunks)} files")
    return n


# ---------------------------------------------------------------------------
# Step 4 — Create chat assistant
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a penetration testing assistant with access to CVE and ExploitDB knowledge bases.\n"
    "Use the following retrieved knowledge to answer:\n{knowledge}\n\n"
    "When given tool output or a vulnerability question, identify relevant CVEs, CVSS scores, "
    "and available exploits. Be concise and factual. "
    "Format: CVE ID | Severity | Affected version | Exploit available (yes/no) | Summary."
)


def create_assistant(dataset_id: str) -> str:
    print("  Creating chat assistant 'nzmweb-pentest'...")
    resp = _rf_post("/api/v1/chats", {
        "name": "nzmweb-pentest",
        "llm": {
            "model_name":  OLLAMA_CHAT,
            "temperature": 0.3,
            "top_p":       0.85,
            "max_tokens":  1024,
        },
        "prompt": {
            "system":         SYSTEM_PROMPT,
            "empty_response": "No relevant CVEs or exploits found in the knowledge base.",
        },
        "dataset_ids": [dataset_id],
    })
    if resp.get("code") != 0:
        raise RuntimeError(f"Assistant creation failed: {resp}")
    chat_id = resp["data"]["id"]
    print(f"  Assistant created: {chat_id}")
    return chat_id


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    print("\n=== RAGFlow rebuild ===\n")

    print("[1/4] Creating dataset")
    dataset_id = create_dataset("CVE-ExploitDB")

    skip_nvd = "--skip-nvd" in sys.argv
    if skip_nvd:
        print("\n[2/4] Skipping NVD (--skip-nvd)")
        cve_count = 30195  # already uploaded
    else:
        print("\n[2/4] Uploading NVD CVEs (HIGH + CRITICAL only, paginated)")
        print("      Estimated time: 15–30 min (NVD rate limit: 1 page/7s)")
        cve_count = upload_nvd(dataset_id)

    print("\n[3/4] Uploading ExploitDB")
    exdb_count = upload_exploitdb(dataset_id)

    print("\n[4/4] Creating chat assistant")
    chat_id = create_assistant(dataset_id)

    print("\n" + "=" * 55)
    print("Done! Update pentest-agent.py lines 36-38 with:")
    print("=" * 55)
    print(f'RAGFLOW_URL  = "{RAGFLOW_URL}"')
    print(f'RAGFLOW_KEY  = "{RAGFLOW_KEY}"')
    print(f'RAGFLOW_CHAT = "{chat_id}"')
    print()
    print(f"Uploaded: {cve_count} CVEs + {exdb_count} ExploitDB entries")
    print(f"Embedding runs in background — check progress:")
    print(f"  {RAGFLOW_URL} → Knowledge Base → CVE-ExploitDB")
    print("Embedding ~80k docs takes 30–90 min on CPU.")


if __name__ == "__main__":
    main()
