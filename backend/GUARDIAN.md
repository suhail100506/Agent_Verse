# Removable Media Guardian

Real, working USB-insertion auto-trigger for CyberVerse. Arm the template, plug in a
USB drive, and the platform automatically runs Malware Analyzer → Privacy Compliance →
Incident Response against the drive's contents and emails one consolidated report —
no button click required.

## How it works

USB insertion is an OS-level event a browser can't see, so detection lives in the
backend (which already runs locally on your machine), not the frontend:

- **`backend/src/cyberverse_orchestrator/usb_guardian.py`** — a background thread
  (started at app startup, same pattern as the existing email poller) polls Windows
  every ~2s via stdlib `ctypes` (`GetLogicalDrives` + `GetDriveTypeW`) for a newly
  mounted removable drive. No extra dependency required.
- On detection, it scans up to 40 files on the drive and runs the **real, unmodified**
  agent flow runners already used everywhere else in the app: `run_malware_flow`,
  `run_privacy_flow`, `run_incident_response_flow`, then one consolidated email via
  the existing `send_report_email`.
- The frontend can't be told about this directly (no push channel), so
  `WorkflowBuilder.jsx` polls `GET /api/triggers/usb/status` every ~1.5s while a USB
  trigger node is on canvas, and mirrors each backend stage onto the matching node's
  status (`running`/`completed`/`error`) — so the canvas animates in near-real-time
  with the actual backend execution.

## The flow (pipeline stages)

```
idle → watching → scanning → malware → privacy → incident → emailing → completed
                                                                       ↘ error (any stage)
```

Reported live via `GET /api/triggers/usb/status`, and reflected onto these canvas
nodes in the "Removable Media Guardian" template:

```
Removable Media Trigger ──► Malware Analyzer Agent ──┐
                       └──► Privacy Compliance Agent ─┴──► Incident Response Agent ──► Final Security Report
```

## Backend endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/triggers/usb/arm` | Arms the watcher with `node_id`, `notify_email`, `credential_id` (called automatically by the frontend whenever a USB trigger node is on canvas) |
| `POST /api/triggers/usb/disarm` | Disarms it |
| `GET /api/triggers/usb/status` | Current stage + results, polled by the frontend |
| `POST /api/triggers/usb/simulate` | Manually fires the same pipeline against a folder (real or synthetic) — no physical drive needed |

## Email notification

One consolidated email is sent at the end via `utils/email_service.py`'s
`send_report_email`, using (in priority order): a bound SMTP credential →
`backend/.env`'s `EMAIL_USER`/`EMAIL_PASS`. If the trigger node's **Notify Email**
field is left blank, the alert still goes out — to whichever address is set as
`EMAIL_USER` in `backend/.env` (or a bound credential's default recipient) — it is
never silently skipped.

## Canvas persistence

The canvas (nodes, edges, and every node's config — Notify Email, bound credential,
system prompt overrides, armed state) is saved to the browser's `localStorage` on
every change and restored on load, so refreshing the page does not reset the
template or lose anything you've configured. Only transient execution state
(running/error spinners) is cleared on reload, since that's stale after a refresh.

## How to test

### A. No USB hardware handy (simulate)

```bash
curl -X POST http://localhost:8000/api/triggers/usb/simulate
curl http://localhost:8000/api/triggers/usb/status   # poll this to watch stages advance
```

Or point it at a specific folder, e.g. the real test kit below:

```bash
curl -X POST http://localhost:8000/api/triggers/usb/simulate \
  -F "root_path=C:\Agent_verse\Cyverse\removable_media_guardian_test_kit"
```

### B. Real USB pendrive

1. Start the backend (`start.bat` from the repo root, or the two-terminal steps in
   the root `README.md`) and open the frontend at `http://localhost:5173`.
2. Sidebar → **Templates** → load **"Removable Media Guardian"**.
3. Click the **Removable Media Trigger** node → set a Notify Email (optional - see
   above) → confirm the popup shows "Armed - watching for USB drive insertion...".
4. Copy the 3 files from `removable_media_guardian_test_kit/` onto a real USB flash
   drive:
   - `employee_records.txt` and `incident_notes.md` — fake SSNs/credit cards/emails,
     reliably trigger Privacy Compliance as `Fake`/HIGH RISK (and prove `.md` files
     get scanned too, not just `.txt`).
   - `setup_helper.bat` — a completely inert script (just prints text, does nothing);
     the Malware Analyzer's extension-based heuristic flags any `.bat`/`.exe`/`.dll`/
     `.vbs` file, so this reliably produces a `Fake`/CRITICAL RISK verdict without
     needing an actual malicious binary.
5. Unplug the drive if already inserted, wait ~2 seconds, then plug it back in. The
   canvas should animate on its own, no clicks: Malware Analyzer → Privacy Compliance
   → Incident Response → Final Security Report.
6. Check the configured inbox for one consolidated "Removable Media Guardian" email.

To re-run, use a different drive or unplug/re-insert the same one — each physical
insertion fires the pipeline exactly once.

## Key files

- `backend/src/cyberverse_orchestrator/usb_guardian.py` — detection, scanning, pipeline
- `backend/src/fake_certificate_verification_agent/main.py` — the 4 endpoints above,
  wired into the existing FastAPI app's startup event
- `frontend/src/data/templates.js` — `buildRemovableMediaGuardianTemplate()`
- `frontend/src/data/nodeLibrary.js` — the `trigger-usb-media` palette entry
- `frontend/src/components/NodePopup.jsx` — trigger node's Notify Email / Armed /
  live status config panel
- `frontend/src/components/WorkflowBuilder.jsx` — auto-arm + status-polling effects,
  canvas `localStorage` persistence
- `removable_media_guardian_test_kit/` — the 3 real test files described above
