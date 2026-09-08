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

Three attacker-facing surfaces (build guide layer 1), sharing one Session
Manager, one Response Engine, and one TTP store/dashboard
(`engine/session_runner.py` is the shared spine):

```
 fake HTTP terminal (/)  ─┐
 fake admin login (/login)├─→  SessionRunner / SessionRegistry
 fake Telnet shell (:2323)│    (engine/session_runner.py)
 fake MySQL wire (:3307) ─┘              │
                                          ▼
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
              three surfaces, tagged by protocol, with TTP trace
```

The three surfaces map directly to the build guide's layer-1 description:

| Surface | Endpoint | What it emulates |
|---|---|---|
| Fake HTTP terminal | `http://localhost:5000/` | interactive shell over HTTP/JSON |
| Fake admin login | `http://localhost:5000/login` | "a fake login flow that behaves like a real misconfigured server" — always fails except a decoy credential planted in the fake `config.php`/`deploy.sh` files, which just leads to another fake page |
| Fake Telnet shell | `telnet localhost 2323` / `nc localhost 2323` | raw-socket line shell, same Session Manager + Response Engine as the HTTP terminal — a genuinely separate transport, not just a second route |
| Fake MySQL listener | `mysql -h 127.0.0.1 -P 3307 -u root -p` | real MySQL protocol v10 handshake + `ERROR 1045 (28000): Access denied` — enough wire protocol to be believable, per build guide 6.2, without parsing real SQL |

`run_honeypot.py` starts all three plus the dashboard together, loading the
GPU model exactly once and sharing it across every surface.

## Project layout

```
honeypot/
  src/
    state/fakefs.py            per-session virtual filesystem + SessionState
    emulation/oracle*.py        deterministic shell simulator (ground truth + fallback)
    emulation/fake_telnet.py    raw-socket Telnet-style shell surface
    emulation/fake_db.py        MySQL wire-protocol handshake + auth-failure surface
    scripts/personas.py         4 synthetic attacker persona scripts
    scripts/gen_dataset.py      runs personas through the Oracle -> labeled dataset
    engine/prompt.py            system prompt + structured-output contract
    engine/train_lora.py        LoRA fine-tuning of the response model
    engine/merge_lora.py        merges adapter into base weights for inference
    engine/response_engine.py   runtime inference + safety fallback
    engine/session_runner.py    shared session/engine/TTP spine for all 3 surfaces
    classifier/features.py      session -> feature vector
    classifier/train.py         trains skill + intent XGBoost classifiers
    classifier/predict.py       runtime classifier wrapper
    ttp/mitre_map.py            command-pattern -> MITRE ATT&CK technique
    ttp/store.py                SQLite TTP log + STIX 2.1 export
    dashboard/app.py            Flask app: fake terminal, fake login, dashboard
  data/
    synthetic/sessions.jsonl   1,000 labeled sessions (classifier training data)
    synthetic/llm_pairs.jsonl  14,192 (state, command) -> (output, delta) pairs
    ttp.db                     live SQLite TTP log (created at runtime)
  models/
    response_lora/             LoRA adapter + eval_metrics.json
    response_merged/           merged standalone model used at inference
    skill_classifier.joblib
    intent_classifier.joblib
    classifier_eval.json / .png
  run_dashboard.py             HTTP surface only
  run_honeypot.py              all three surfaces + dashboard together
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

# run all three surfaces + dashboard together
python run_honeypot.py
# or, HTTP surface only:
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
- `telnet localhost 2323` (or `nc localhost 2323`) — the fake Telnet shell
- `mysql -h 127.0.0.1 -P 3307 -u root -p` — the fake MySQL listener
- `http://localhost:5000/dashboard` — live session list across all four
  entry points, skill/intent classification, per-command MITRE trace

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
