# CyberVerse — AI Multi-Agent Cybersecurity Platform

An n8n-style visual workflow builder (React Flow) for cybersecurity automation, backed by a FastAPI service that runs 10 specialized agents plus a master orchestrator, all reasoning with real Groq LLM calls.

- **Frontend**: React 19 + Vite + `@xyflow/react`, at `frontend/`
- **Backend**: FastAPI + `litellm` (Groq), at `backend/`

## Prerequisites

- Python 3.10–3.13 with [`uv`](https://docs.astral.sh/uv/) installed
- Node.js 18+ and npm
- A [Groq API key](https://console.groq.com/keys) (for real LLM-backed agent reasoning — agents still work without one, falling back to heuristic-only analysis)

> **Where does the Groq key go?** You do **not** need to put it in `.env`. The recommended way is to add it from the running app's UI (Credential Vault), so it's stored encrypted on the backend and can be swapped per-node. See [step 4](#4-add-your-groq-api-key-from-the-ui) below. `.env`'s `GROQ_API_KEY` still works as a server-wide fallback if you prefer that instead — see [Alternative: env-based key](#alternative-env-based-key).

## 1. Configure the credential vault key

```bash
cd backend
cp .env.example .env
```

Generate a permanent vault encryption key so credentials you add from the UI survive backend restarts:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Paste the output into `VAULT_ENCRYPTION_KEY=` in `backend/.env`. (If you skip this, a temporary key is generated per-run and any credentials you add will be lost on the next restart — fine for a quick try, not for real use.)

## 2. Run the backend

Still inside `backend/` from step 1 (don't `cd backend` again — a second `cd backend` from here will fail with "path does not exist"):

```bash
uv sync
uv run python -m uvicorn src.fake_certificate_verification_agent.main:app --reload --port 8000
```

> **Windows/PowerShell note:** use `uv run python -m uvicorn ...`, not `uv run uvicorn ...` — on some `uv` versions, passing `uvicorn` directly hits a bug where the `:` in `main:app` gets misparsed as a script path and fails with `Failed to canonicalize script path`. Routing it through `python -m` avoids that.

Backend will be live at **http://localhost:8000**. Check it with:

```bash
curl http://localhost:8000/api/health
```

## 3. Run the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend will be live at **http://localhost:5173**.

### One-command start (Windows)

From the repo root, double-click `start.bat` (or run it from a terminal). It launches both servers in a single window with interleaved logs — closing the window or `Ctrl+C` stops both.

```bash
start.bat
```

## 4. Add your Groq API key from the UI

With both servers running, open **http://localhost:5173** and add your key to the vault one of two ways:

- **Sidebar → Credentials tab** — click **Add Credential**, choose type **Groq API Key**, give it a name, paste your key, and Save. This key is now available to bind to any node.
- **Directly on a node** — click any agent node to open its popup, go to the **Credentials** tab, click **+ Add Credential**, and save it the same way. The popup immediately binds the new credential to that node.

Once saved, a node using that credential shows a green "Using `<name>` (`masked...key`)" banner at the top of its popup. The raw key is encrypted at rest and is never sent back to the browser after saving — only a masked preview (e.g. `gsk_...ab12`) is ever shown.

You can add multiple Groq keys (e.g. one per team/environment) and bind different nodes to different keys — each node only uses the credential explicitly bound to it; nodes with no credential bound fall back to the server's `GROQ_API_KEY` env var if one is set, or to heuristic-only analysis if not.

### Alternative: env-based key

If you'd rather configure one key for the whole server instead of using the UI, add it to `backend/.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Any node with no credential bound will use this automatically.

---

## Testing the platform

### A. Backend sanity checks

```bash
# Health check - lists all 11 agents (10 specialists + master orchestrator)
curl http://localhost:8000/api/health

# Create a credential (stored encrypted; never returned in plaintext)
curl -X POST http://localhost:8000/api/credentials \
  -F name="My Groq Key" -F type=groq_api_key -F api_key=YOUR_GROQ_KEY

# List credentials - confirm only a masked preview is shown, never the raw key
curl http://localhost:8000/api/credentials

# Run an agent directly
curl -X POST http://localhost:8000/api/analyze/phishing -F url_or_text="http://paypal-secure-verify.tmp/login"

# Run the master orchestrator and confirm it classifies correctly
curl -X POST http://localhost:8000/api/orchestrator/analyze -F prompt="check this password strength: hunter2"
# -> router_diagnostics.selected_agent should be "Password Security Advisor Agent"

curl -X POST http://localhost:8000/api/orchestrator/analyze -F prompt="urgent, this is your CEO, wire transfer gift cards now"
# -> should route to Fraud Detection or Social Engineering / Deepfake Detection Agent
```

To confirm Groq reasoning is actually active (not just heuristics), check the `llm_reasoning_used` and `llm_source` fields in any agent's JSON response — `llm_source` will read `"env-default"` or `"credential:CRED-..."` when a real Groq call succeeded, or `"unavailable"` if it fell back to heuristics only (e.g. no key configured).

### B. Frontend click-through

With both servers running, open **http://localhost:5173** and verify:

1. **Node popup** — click any node on the canvas. A small floating card should appear anchored near where you clicked (not a full-height side panel). Try the **Config**, **Credentials**, **Payload**, and **Logs** tabs.
2. **Credential binding** — in a node's popup, go to the Credentials tab, add a new Groq API key credential, and confirm it appears in the dropdown and gets bound to that node. Reload the page and confirm the credential still exists (it's stored server-side).
3. **Agents playground** — open the left Sidebar's **Agents** tab, expand an agent card, edit its system prompt or model, then drag it onto the canvas. Click the new node and confirm the popup's Config tab shows your edited prompt.
4. **Templates** — open the Sidebar's **Templates** tab (or the header's Templates button) and load a few of the 11 templates. You should see 10 single-agent pipelines (one per specialist agent) plus one **Master Orchestration** template wiring all 10 agents behind the orchestrator.
5. **Run a workflow** — wire (or load a template with) an ingest node → an agent node → the report node, type a payload into the ingest node, and click **Run Node**. Watch the edge animate and the target node's status update to Running → Completed, with the result panel showing the agent's response.
6. **Vault tab** — open the Sidebar's **Credentials/Vault** tab and confirm it shows your real saved credentials (masked), not placeholder data.

### C. Webhook trigger (optional, v1 scope)

Webhook trigger nodes register themselves automatically while the app is open (whenever you connect one to a downstream agent). With the frontend open and a Webhook node wired to an agent:

```bash
curl -X POST http://localhost:8000/api/triggers/webhook/<webhook-node-id> -F text="some payload"
```

The node's popup shows the exact URL to use (Config tab, when a Webhook Listener node is selected).

---

## Project structure

```
backend/
  src/
    <agent>_agent/flow_runner.py     # one per specialist agent - heuristics + Groq LLM layer
    cyberverse_orchestrator/         # master router, credential vault, auth, report export
    utils/                          # shared llm_client.py and email_service.py
    fake_certificate_verification_agent/main.py   # the FastAPI app entrypoint (all routes)
frontend/
  src/
    components/                     # WorkflowBuilder, WorkflowCanvas, AgentNode, NodePopup, Sidebar, ...
    data/                           # nodeLibrary.js, agentLibrary.js, agentRoutes.js, templates.js
```
