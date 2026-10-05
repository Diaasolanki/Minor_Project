# How to Run — Adaptive AI Honeypot

This project has no external API keys. The response engine is a locally
fine-tuned open-weight LLM; the skill/intent classifiers are locally trained
XGBoost models. Everything runs on your own machine.

## 1. Prerequisites

- Windows with an NVIDIA GPU (tested on an RTX 4070, 12GB). CPU-only works but
  generation will be much slower.
- Python 3.10+.

## 2. One-time setup

```bash
cd honeypot
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

The trained LoRA adapter and classifiers are included in this repo under
`honeypot/models/` (small enough for git), and the synthetic training data is
included under `honeypot/data/synthetic/`.

The **merged** inference model (`honeypot/models/response_merged/`, ~2.9GB)
is intentionally **not** in the git repo — it's a rebuilt-from-the-adapter
artifact, too large for a normal git push. The app works fine without it:
`response_engine.py` automatically falls back to loading the base model +
LoRA adapter directly if `response_merged/` is missing (a few seconds slower
to start, functionally identical). If you want the faster merged form, run:

```bash
python src/engine/merge_lora.py
```

once after cloning — it rebuilds `response_merged/` from the included adapter
in under a minute (no GPU retraining needed). Everything else (classifiers,
adapter, synthetic data) works immediately after `pip install`, so you can
skip straight to **Section 4 — Running the honeypot**.

If you want to regenerate everything from scratch instead (new synthetic
data, retrained classifiers, retrained LoRA), see Section 5.

## 3. What gets installed

`requirements.txt` installs PyTorch (CUDA build), Transformers, PEFT,
scikit-learn, XGBoost, Flask, and supporting libraries — no paid API SDKs.

## 4. Running the honeypot

From the `honeypot/` directory, with the virtual environment activated:

```bash
# all five attacker surfaces + dashboard together (recommended)
python run_honeypot.py

# or, HTTP surfaces only (fake terminal, login, vulnerable web portal —
# skips the raw-socket Telnet/DB listeners)
python run_dashboard.py
```

The first run loads the fine-tuned model onto the GPU, which takes a few
seconds. Once you see `[engine] model ready` in the console, everything is up.

### Where to go

| Surface | How to reach it |
|---|---|
| Fake terminal | Open `http://localhost:5000/` in a browser |
| Fake admin login | Open `http://localhost:5000/login` in a browser |
| Fake vulnerable web portal | Open `http://localhost:5000/portal/login` in a browser |
| Fake Telnet shell | `telnet localhost 2323` (or `nc localhost 2323`) |
| Fake MySQL listener | `mysql -h 127.0.0.1 -P 3307 -u root -p` |
| Live dashboard | Open `http://localhost:5000/dashboard` in a browser |

### Trying the vulnerable web portal

The portal (`/portal/login`) is a fake "TechCorp" employee intranet with four
genuinely exploitable — but fully contained and fake — vulnerabilities, each
logged and MITRE-mapped like every other surface:

| Vulnerability | How to trigger it | MITRE technique |
|---|---|---|
| SQL injection (auth bypass) | At `/portal/login`, enter username `' OR '1'='1' --` with any password | T1190 |
| Stored XSS | Log in, then post `<script>alert(1)</script>` as feedback on the dashboard | T1059 |
| IDOR (view another user) | While logged in as a low-privilege user, visit `/portal/profile?user_id=1` | T1078 |
| Privilege escalation | On your own profile page, change the "Role" dropdown to Admin and save | T1078 |
| Weak/default admin credentials | At `/portal/admin`, log in with `admin` / `admin123` | T1078 |

None of this touches your real filesystem, a real database beyond a small
local SQLite decoy (`honeypot/data/portal.db`, seeded with fake employees),
or any real user data — it exists purely to give the classifier a genuine web
-attack surface to observe, the same way the shell/Telnet/DB surfaces give it
a genuine command-line surface.

### Using the dashboard

1. Interact with any surface above to generate sessions (type shell commands,
   try logging in, try the portal's vulnerabilities, or connect via a
   telnet/mysql client).
2. Open the dashboard and use the protocol tabs (All / HTTP shell / Telnet /
   DB / Login / Web Portal) to filter sessions.
3. Click a session row to load its command trace.
4. Use **Play / Step / Reset** and the speed selector to replay a session
   like a recording.
5. Click **Download STIX** to export that session as a STIX 2.1 bundle.
6. Scroll down to the **Evaluation** panel for live classifier F1 scores,
   MITRE ATT&CK technique frequency, response-engine usage, latency, and
   engagement time — it refreshes automatically every 5 seconds.

## 5. Regenerating everything from scratch (optional)

Only needed if you change the persona scripts, the Oracle's command handlers,
or want to retrain on more data.

```bash
# 1. Regenerate the synthetic training data (1,000 labeled attacker sessions)
python src/scripts/gen_dataset.py 1000

# 2. Train the skill/intent classifiers (seconds)
python src/classifier/train.py
python src/classifier/eval_report.py

# 3. Fine-tune the local response model (long-running, GPU required —
#    roughly 8 hours for 3 epochs over ~14k examples on an RTX 4070)
python src/engine/train_lora.py

# 4. Merge the LoRA adapter into the base weights for faster inference
python src/engine/merge_lora.py
```

The training script checkpoints every epoch and resumes automatically if
interrupted — just re-run `python src/engine/train_lora.py` and it will pick
up from the last saved checkpoint instead of starting over.

## 6. Project layout

```
honeypot/
  src/
    state/fakefs.py            per-session virtual filesystem + SessionState
    emulation/oracle*.py        deterministic shell simulator (ground truth + fallback)
    emulation/fake_telnet.py    raw-socket Telnet-style shell surface
    emulation/fake_db.py        MySQL wire-protocol handshake + auth-failure surface
    emulation/fake_webapp.py    fake vulnerable web portal (SQLi, XSS, IDOR, weak creds)
    scripts/personas.py         4 synthetic attacker persona scripts
    scripts/gen_dataset.py      runs personas through the Oracle -> labeled dataset
    engine/prompt.py            system prompt + structured-output contract
    engine/train_lora.py        LoRA fine-tuning of the response model
    engine/merge_lora.py        merges adapter into base weights for inference
    engine/response_engine.py   runtime inference + safety fallback
    engine/session_runner.py    shared session/engine/TTP spine for all 5 surfaces
    classifier/features.py      session -> feature vector
    classifier/train.py         trains skill + intent XGBoost classifiers
    classifier/predict.py       runtime classifier wrapper
    ttp/mitre_map.py            command-pattern -> MITRE ATT&CK technique
    ttp/store.py                SQLite TTP log + metrics + STIX 2.1 export
    dashboard/app.py            Flask app: fake terminal, fake login, web portal, dashboard
    dashboard/templates/        terminal.html, login.html, dashboard.html, portal_*.html
  data/
    synthetic/sessions.jsonl    1,000 labeled sessions (classifier training data)
    synthetic/llm_pairs.jsonl   14,192 (state, command) -> (output, delta) pairs
    ttp.db                      live SQLite TTP log (created at runtime)
    portal.db                   fake employee DB for the web portal (created at runtime)
  models/
    response_lora/              LoRA adapter + eval_metrics.json
    response_merged/            merged standalone model used at inference
    skill_classifier.joblib
    intent_classifier.joblib
    classifier_eval.json / .png
  run_dashboard.py               HTTP-based surfaces only
  run_honeypot.py                all five surfaces + dashboard together
  requirements.txt
```

## 7. Troubleshooting

- **`ModuleNotFoundError`** — make sure the virtual environment is activated
  and `pip install -r requirements.txt` completed successfully.
- **Model loads but responses are slow (5–25s)** — expected on this hardware;
  see the "Known limitations" section of `honeypot/README.md`.
- **Port already in use** — another process is bound to 5000/2323/3307. Set
  `TELNET_PORT` / `DB_PORT` environment variables to change the fake Telnet /
  DB ports, or stop the conflicting process for port 5000.
- **No GPU / CUDA not available** — the response engine will still run on
  CPU, just much slower per command; the deterministic Oracle fallback keeps
  the honeypot usable in the meantime.


reimplemented against this project's own session/TTP/classifier pipeline.
HoneyScope's SIEM (Wazuh), SSH honeypot (Cowrie), Raspberry Pi cold-storage
node, and Gemini-based AI analysis were deliberately **not** ported — see
`honeypot/README.md` for why.
