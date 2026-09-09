# Adaptive AI Honeypot

An LLM-driven deception system that generates believable, stateful fake shell
output for an attacker session, logs every command as MITRE-mapped TTP data,
and classifies the attacker's skill level and intent in real time — all with
**no external API key**. The response model is a locally fine-tuned open-weight
LLM running on-box.

Built from the project brief in [`Adaptive_AI_Honeypot_Build_Guide.docx`](../Adaptive_AI_Honeypot_Build_Guide.docx),
adapted to a single-machine coursework deployment (SQLite instead of
Postgres+Redis, Flask instead of React+WebSockets — same architecture and
request flow, smaller footprint).

## What's actually trained here

Two genuinely trained models, not prompt-engineered wrappers around a hosted API:

1. **Response Engine** — `Qwen/Qwen2.5-1.5B-Instruct`, LoRA fine-tuned (rank 16,
   all attention + MLP projections, 18.5M trainable params) on 14,192
   `(session_state, command) -> (display_output, state_delta)` pairs generated
   by a deterministic Oracle simulator. 3 epochs, final `eval_loss = 0.0101`.
   The adapter is merged into the base weights (`models/response_merged/`) for
   inference. Runs entirely on the local GPU; never calls out to OpenAI/Claude/
   any hosted API.
2. **Skill + Intent Classifiers** — two independent XGBoost models over 15
   hand-engineered session features (command diversity, obfuscation count,
   priv-esc/persistence/anti-forensic signal, MITRE technique/tactic spread,
   error ratio, etc.), trained on 1,000 labeled synthetic sessions across 4
   attacker personas. Held-out (80/20) results:
   - Skill classifier: **100% accuracy** (the 4 persona archetypes are cleanly
     separable on these features — expected for scripted personas, worth
     validating against messier real/public data before trusting in the wild).
   - Intent classifier: **87% accuracy**; the main confusion is
     `cryptomining` vs `botnet_recruitment` (both draw from the same
     scripted-bot behavioral branch and share features) — see
     `models/classifier_eval.png` for the per-class F1 breakdown.

## Why a trained local model instead of an API-backed one

The brief's default recommendation is a hosted LLM (Claude/GPT) for the demo
with local fine-tuning as a stretch goal. Per this project's requirement, the
stretch goal is the whole implementation: an Oracle-generated synthetic corpus
supervises a small open model well enough to reproduce realistic, stateful
Ubuntu shell behavior without ever touching a paid API.

## Architecture

Five attacker-facing surfaces (build guide layer 1), sharing one Session
Manager, one Response Engine, and one TTP store/dashboard
(`engine/session_runner.py` is the shared spine):

```
 fake HTTP terminal (/)          ─┐
 fake admin login (/login)        │
 fake vulnerable web portal       ├─→  SessionRunner / SessionRegistry
   (/portal/*: SQLi, XSS, IDOR)   │    (engine/session_runner.py)
 fake Telnet shell (:2323)        │              │
 fake MySQL wire (:3307)         ─┘              ▼
                          Session Manager (state/fakefs.py)
                          per-session fake filesystem, users, cwd, env
                                          │
                                          ▼
                       Response Engine (engine/response_engine.py)
              local fine-tuned LLM → JSON {display_output, state_delta}
                       │ malformed/unsafe output? │
                       ▼                          ▼
              apply state_delta          Oracle fallback (never stalls,
                                          never breaks character)
                                          │
                                          ▼
                    TTP Logger (ttp/store.py, SQLite)
                    + MITRE mapping (ttp/mitre_map.py)
                                          │
                                          ▼
                Skill/Intent Classifier (classifier/predict.py)
                                          │
                                          ▼
              Dashboard (/dashboard) — live sessions across all
              five surfaces, tagged by protocol, with TTP trace
```

The five surfaces map to the build guide's layer-1 description (the web
portal additionally covers the "fake vulnerable web application" angle from
the HoneyScope project — see **Acknowledgements** below):

| Surface | Endpoint | What it emulates |
|---|---|---|
| Fake HTTP terminal | `http://localhost:5000/` | interactive shell over HTTP/JSON |
| Fake admin login | `http://localhost:5000/login` | "a fake login flow that behaves like a real misconfigured server" — always fails except a decoy credential planted in the fake `config.php`/`deploy.sh` files, which just leads to another fake page |
| Fake vulnerable web portal | `http://localhost:5000/portal/login` | a fake "TechCorp" intranet with four genuinely exploitable, fully contained vulnerabilities: SQL injection auth bypass, stored XSS, IDOR/privilege escalation, and a weak-credential hidden admin panel — each MITRE-mapped and logged like every other surface |
| Fake Telnet shell | `telnet localhost 2323` / `nc localhost 2323` | raw-socket line shell, same Session Manager + Response Engine as the HTTP terminal — a genuinely separate transport, not just a second route |
| Fake MySQL listener | `mysql -h 127.0.0.1 -P 3307 -u root -p` | real MySQL protocol v10 handshake + `ERROR 1045 (28000): Access denied` — enough wire protocol to be believable, per build guide 6.2, without parsing real SQL |

`run_honeypot.py` starts all five plus the dashboard together, loading the
GPU model exactly once and sharing it across every surface.

## Project layout

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
    ttp/store.py                SQLite TTP log + STIX 2.1 export
    dashboard/app.py            Flask app: fake terminal, login, web portal, dashboard
    dashboard/templates/        terminal.html, login.html, dashboard.html, portal_*.html
  data/
    synthetic/sessions.jsonl   1,000 labeled sessions (classifier training data)
    synthetic/llm_pairs.jsonl  14,192 (state, command) -> (output, delta) pairs
    ttp.db                     live SQLite TTP log (created at runtime)
    portal.db                  fake employee DB for the web portal (created at runtime)
  models/
    response_lora/             LoRA adapter + eval_metrics.json
    response_merged/           merged standalone model used at inference
    skill_classifier.joblib
    intent_classifier.joblib
    classifier_eval.json / .png
  run_dashboard.py             HTTP-based surfaces only
  run_honeypot.py              all five surfaces + dashboard together
  requirements.txt
```

## Running it

```bash
cd honeypot
python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt

# The LoRA adapter, both classifiers, and the synthetic training data are
# already in this repo (models/response_lora/, models/*.joblib,
# data/synthetic/) — nothing to train before you can run the honeypot.
#
# The merged inference model (models/response_merged/, ~2.9GB) is NOT
# checked into git — it's rebuilt from the adapter above. Either skip this
# (response_engine.py falls back to base model + adapter automatically,
# a few seconds slower to start) or rebuild it once, no GPU training needed:
python src/engine/merge_lora.py

# run all five surfaces + dashboard together
python run_honeypot.py
# or, HTTP-based surfaces only:
python run_dashboard.py
```

To regenerate the synthetic dataset, classifiers, or the LoRA adapter itself
from scratch instead of using what's checked in:

```bash
python src/scripts/gen_dataset.py 1000   # synthetic sessions + LLM training pairs
python src/classifier/train.py           # skill + intent XGBoost classifiers
python src/engine/train_lora.py          # LoRA fine-tune (long-running, GPU required —
                                          # ~8 hours for 3 epochs on an RTX 4070;
                                          # checkpoints every epoch and resumes if interrupted)
python src/engine/merge_lora.py          # merge the new adapter for inference
```

Then:
- `http://localhost:5000/` — the fake terminal an "attacker" interacts with
- `http://localhost:5000/login` — the fake admin login page
- `http://localhost:5000/portal/login` — the fake vulnerable web portal
  (SQLi bypass: username `' OR '1'='1' --`; stored XSS via the feedback box;
  IDOR via `/portal/profile?user_id=1`; weak admin creds `admin`/`admin123`
  at `/portal/admin` — see HOW_TO_RUN.md for the full walkthrough)
- `telnet localhost 2323` (or `nc localhost 2323`) — the fake Telnet shell
- `mysql -h 127.0.0.1 -P 3307 -u root -p` — the fake MySQL listener
- `http://localhost:5000/dashboard` — live session list across all five
  entry points, skill/intent classification, per-command MITRE trace

## Acknowledgements

The fake vulnerable web portal (`src/emulation/fake_webapp.py`,
`/portal/*`) adapts the four intentional web vulnerabilities from the
"Website" component of [HoneyScope](https://github.com/Guptaharshal1515/HoneyScope)
(SQL injection auth bypass, stored XSS, IDOR + privilege escalation, weak
admin credentials). The vulnerability *mechanics* are reproduced faithfully;
the *plumbing* is entirely this project's own — a Flask blueprint wired into
`engine/session_runner.py` so every exploit attempt is logged, MITRE-mapped,
and fed to the same skill/intent classifier as the shell/Telnet/DB surfaces.

What was **not** ported from HoneyScope, and why:

| HoneyScope component | Why it's out of scope here |
|---|---|
| Cowrie SSH honeypot | This project's fake Telnet shell (`fake_telnet.py`) already covers "fake interactive shell over a raw socket protocol"; adding a second, heavier SSH-protocol implementation on top would duplicate that surface without adding a new capability. |
| Wazuh SIEM + custom detection rules | This project's own TTP store + MITRE mapping + dashboard (`ttp/store.py`, `ttp/mitre_map.py`, `/dashboard`) already serves the same role — event correlation and technique tagging — at single-machine scale. Standing up a second SIEM alongside it would be pure infrastructure duplication for a coursework build. |
| Gemini 2.5 Flash AI analysis | Directly conflicts with this project's core requirement: **no external LLM API calls, anywhere.** The equivalent capability here is the locally fine-tuned response engine plus the locally trained skill/intent classifier — both already produce the "attacker behavior profile" HoneyScope gets from a hosted API call. |
| Raspberry Pi cold-storage log node | Requires a second physical device and a multi-machine network topology; orthogonal to what this project demonstrates (a self-contained, single-machine honeypot with a trained local model). |
| Multi-VM deployment (VM1/VM2 + iptables port redirection) | Real network isolation is exactly the kind of production-hardening step called out as future work in the original build guide's own section 6 — appropriate for a real deployment, not needed to demonstrate the deception/classification pipeline locally. |

## Known limitations (honest accounting, not hidden)

- **Latency**: unbatched bf16 generation on this hardware runs ~1.2s for short
  outputs up to ~20-25s for long multi-line dumps (e.g. `cat /etc/passwd`),
  above the build guide's <1.5s target. Root cause is per-token autoregressive
  decoding without flash-attention (unavailable on Windows) or a serving
  engine like vLLM/TensorRT-LLM. Mitigations from the build guide's own risk
  table (response caching for common commands, a smaller/quantized model) are
  the natural next step, not yet implemented.
- **Classifier training data is entirely synthetic.** Skill separates
  perfectly because the 4 personas are procedurally distinct by construction;
  real attacker traffic will be messier. The build guide's own suggestion —
  mixing in real public Cowrie/T-Pot sessions for validation — has not been
  done here.
- **Isolation/deployment hardening** (containers, egress filtering, VPC
  placement — build guide section 6) is out of scope for this local
  coursework build; the code-level safety property that matters (no
  `subprocess`/`exec`/`eval` on attacker input, anywhere) is upheld in both
  the Oracle and the Response Engine's fallback path.
