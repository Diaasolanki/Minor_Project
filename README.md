# Adaptive AI Honeypot (Minor Project)

An LLM-driven deception system that generates believable, stateful fake shell output for attacker sessions, logs every interaction as MITRE ATT&CK-mapped TTP data, and classifies the attacker's skill level and intent in real time — with **zero external API keys**. Everything runs locally on-box using locally trained and fine-tuned models.

---

## 🚀 Key Highlights

- **Local Response Engine**: Fine-tuned `Qwen/Qwen2.5-1.5B-Instruct` with LoRA on 14,000+ structured `(state, command) -> (output, delta)` interaction pairs.
- **Skill & Intent Classifiers**: Two independent XGBoost classifiers operating over 15 hand-engineered behavioral features (100% skill accuracy, 87% intent accuracy on test set).
- **Zero Paid API Dependencies**: Completely offline and self-contained; no OpenAI, Anthropic, or external API keys needed.
- **5 Attacker Surfaces**:
  1. **Interactive Web Terminal** (`http://localhost:5000/`)
  2. **Fake Admin Login** (`http://localhost:5000/login`)
  3. **Fake Vulnerable Web Portal** (`http://localhost:5000/portal/login` — SQLi, stored XSS, IDOR, weak admin credentials)
  4. **Fake Telnet Shell** (`telnet localhost 2323` / `nc localhost 2323`)
  5. **Fake MySQL Service** (`mysql -h 127.0.0.1 -P 3307 -u root -p`)
- **Live SOC Dashboard**: Real-time session monitoring, MITRE ATT&CK technique mapping, and STIX 2.1 export at `http://localhost:5000/dashboard`.

---

## 📁 Repository Structure

```
Minor Project/
├── HOW_TO_RUN.md                               # Step-by-step setup & operational guide
├── Adaptive_AI_Honeypot_Build_Guide.docx       # Architecture design document
├── Adaptive_AI_Honeypot_Features_and_Usage.docx# Complete feature documentation
└── honeypot/
    ├── README.md                               # Detailed technical honeypot docs
    ├── run_honeypot.py                         # Launches all 5 surfaces + dashboard
    ├── run_dashboard.py                        # Launches web surfaces only
    ├── requirements.txt                        # Python dependencies
    ├── src/
    │   ├── classifier/                         # XGBoost feature extraction & models
    │   ├── dashboard/                          # Flask web interface & templates
    │   ├── emulation/                          # Shell oracle, fake webapp, Telnet, MySQL
    │   ├── engine/                             # LoRA response engine & session runner
    │   ├── scripts/                            # Dataset generation & synthetic personas
    │   ├── state/                              # In-memory virtual filesystem (fakefs)
    │   └── ttp/                                # MITRE ATT&CK mapping & SQLite logger
    ├── data/
    │   └── synthetic/                          # Pre-generated synthetic training data
    └── models/
        ├── response_lora/                      # Fine-tuned LoRA weights
        ├── skill_classifier.joblib             # Trained skill model
        ├── intent_classifier.joblib            # Trained intent model
        └── classifier_eval.png                 # Evaluation confusion matrix & metrics
```

---

## ⚡ Quick Start

For detailed execution and testing instructions, please read [HOW_TO_RUN.md](HOW_TO_RUN.md).

### 1. Setup Virtual Environment
```bash
cd honeypot
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Honeypot
```bash
# Starts all five attack surfaces + the live monitoring dashboard
python run_honeypot.py
```

Open your browser to:
- Attacker Terminal: [http://localhost:5000/](http://localhost:5000/)
- SOC Monitoring Dashboard: [http://localhost:5000/dashboard](http://localhost:5000/dashboard)
- Vulnerable Portal: [http://localhost:5000/portal/login](http://localhost:5000/portal/login)