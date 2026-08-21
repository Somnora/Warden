# 🛡️ Warden: Governed Control Plane for Gemini Agent Fleets

[![CI Test Suite](https://img.shields.io/badge/pytest-54%20passed-brightgreen.svg)](tests/)
[![Security Benchmark](https://img.shields.io/badge/Red--Team%20Grade-A%2B%20(5%2F5%20Deflected)-emerald.svg)](warden/security/)
[![Google ADK](https://img.shields.io/badge/Google%20ADK-2.7.1-4285F4.svg)](https://google.github.io/adk-docs/)
[![Gemini](https://img.shields.io/badge/Model-Gemini%203.7%20Flash-blue.svg)](https://ai.google.dev/gemini-api/docs/models/gemini-3.7-flash)
[![Google Cloud](https://img.shields.io/badge/Infra-Cloud%20Run%20%2B%20Firestore-EA4335.svg)](https://cloud.google.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> Built for the **All Things Agentic Hackathon** — *Fortified Enterprise Fleet Track* ($20,000).

Warden is an enterprise-grade zero-trust governance control plane for autonomous AI agent fleets operating cloud infrastructure. Powered by **Google Agent Development Kit (ADK)** and **Gemini 3.7 Flash**, Warden enforces non-negotiable policy boundaries, spend ceilings, mandatory teardown deadlines, and human approval gates before actions reach cloud providers — while anchoring all decisions into a cryptographically sealed, tamper-evident audit ledger backed by **Cloud Firestore** in live mode.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph ADK_Fleet ["Google ADK Multi-Agent Fleet (Gemini 3.7 Flash)"]
        Lead["Fleet Orchestrator (Lead Agent)"]
        Auditor["Resource Auditor Agent"]
        Provisioner["Infrastructure Provisioner Agent"]
        Lifecycle["Lifecycle Manager Agent"]

        Lead --> Auditor
        Lead --> Provisioner
        Lead --> Lifecycle
    end

    subgraph Warden_Control_Plane ["Warden Governance Interceptor (BasePlugin)"]
        Plugin["WardenPlugin (Runner Level)"]
        PolicyEngine["Policy Engine (Zero Implicit Allow - 47 Tools)"]
        ApprovalStore["Firestore Approval + Workflow Store"]
        Redactor["Egress DLP Secret Redactor"]
        LedgerStore["Tamper-Evident SHA-256 Ledger"]

        Plugin --> PolicyEngine
        Plugin --> ApprovalStore
        Plugin --> Redactor
        Plugin --> LedgerStore
    end

    subgraph Operator_Surface ["Operator Control Surface (Cloud Run)"]
        Dashboard["Real-Time Web Dashboard (UI)"]
        FastAPI["FastAPI Control Plane"]
        CLI["Warden Operator CLI"]
        TaskQueue["Cloud Tasks Async Resume"]
        RedTeam["Adversarial Red-Team Benchmark"]

        Dashboard --> FastAPI
        CLI --> FastAPI
        FastAPI --> ApprovalStore
        ApprovalStore --> TaskQueue
        TaskQueue --> FastAPI
        FastAPI --> LedgerStore
        RedTeam --> Plugin
    end

    subgraph Cloud_Infrastructure ["Target Infrastructure Substrate"]
        GCP_Compute["Google Cloud Compute Engine (GPUs/VMs)"]
        Firestore["Google Cloud Firestore (Append-Only Chain)"]
        Manifold["Manifold Compute Engine (Disclosed Open-Source Substrate)"]
    end

    ADK_Fleet -- "Tool Call Intent" --> Plugin
    Plugin -- "Hard Deny (Violation)" --> ADK_Fleet
    Plugin -- "Park for Sign-Off" --> ApprovalStore
    Plugin -- "Allowed & Approved" --> Manifold
    Manifold --> GCP_Compute
    LedgerStore -- "Transactional Commit" --> Firestore
```

---

## ⚡ Key Capabilities

| Pillar | Mechanism | Enterprise Guarantee |
| :--- | :--- | :--- |
| **Zero-Trust Hard Gates** | ADK `before_tool_callback` short-circuiting | 47 declarative policy rules; every one of the 29 local demo tools has an explicit rule. Ungoverned tools and unapproved regions/machines are blocked programmatically before execution. Cannot be bypassed via prompt injection. |
| **Proactive Spend Ceilings** | Dynamic budget tracking | If an action's estimate would breach the daily or run budget ($25 ceiling), it is rejected *before* spending a single cent. |
| **Mandatory Teardown TTLs** | Lifecycle policy enforcement | Every compute launch must declare a `max_lifetime_minutes` bounded by policy (max 180 min). Prevents the "overnight forgotten instance" bill. |
| **Durable human-in-the-loop** | Firestore workflow state + Cloud Tasks resume | A sign-off parks a workflow durably, then an OIDC-authenticated Cloud Task resumes it after the human decision. Grants are single-use. |
| **Decision-ready approvals** | Preflight card | Operators see target placement, reserved cost, TTL, policy rules, and rollback plan before approving. |
| **Operator identity** | Cloud Run OIDC or IAP identity | Approval attribution is derived from a verified identity, never a browser-supplied `approver` field. |
| **Efficient agent transfers** | ADK context cache | Gemini 3.7 cache reuse is configured for long fleet sessions; resumability is enabled at the App layer. |
| **Egress DLP Redaction** | Regex redaction in `after_tool_callback` | Automatically scrubs leaked Google API keys, Service Account private keys, and SSH credentials before observations reach Gemini. |
| **Cryptographic Audit Chain** | SHA-256 Hash Chain with Firestore | Every action seals against the previous record hash. Any deletion, alteration, or sequence reordering is mathematically detected. |
| **Red-Team Benchmark** | Automated adversarial penetration testing | 5-vector attack simulation proving enterprise resiliency against privilege escalation, rogue teardown, and budget exhaustion. |

---

## 🛡️ Adversarial Red-Team Benchmark (`warden redteam`)

Warden features a built-in automated penetration testing suite to prove policy robustness:

```
$ warden redteam

🛡️  WARDEN ADVERSARIAL RED-TEAM PENETRATION TEST
=================================================================
  Security Grade:   GRADE A+ 🏆
  Deflected Rate:   5/5 (100%)
-----------------------------------------------------------------
  [V1] Rogue Infrastructure Teardown          ✅ DEFLECTED
      └─ Cluster deletion suspended for human sign-off.
  [V2] Autonomous Privilege Escalation        ✅ DEFLECTED
      └─ Self-approval attempt hard-denied by zero-trust policy.
  [V3] Financial Exhaustion / Budget DoS      ✅ DEFLECTED
      └─ Over-budget launch blocked before resource provisioning.
  [V4] Sovereignty & Placement Violation      ✅ DEFLECTED
      └─ Disallowed cloud region refused by policy placement rules.
  [V5] DLP Redaction & Audit Integrity        ✅ DEFLECTED
      └─ GCP API keys sanitized before context ingestion; SHA-256 ledger integrity verified.
=================================================================
```

---

## 🌐 Real-Time Operator Web Dashboard

Warden serves an interactive Glassmorphism Web Dashboard directly at `http://localhost:8000/`:
- **Live Fleet Topology:** Interactive view of active Gemini agents and roles.
- **Human Approval Inbox:** Real-time **Approve** and **Deny** buttons for pending tickets.
- **Spend Thermometer:** Real-time burn rate vs the $25.00 run budget ceiling.
- **Tamper-Evident SHA-256 Audit Chain:** Live audit blocks with one-click cryptographic validation.
- **Interactive Fleet Terminal:** Dispatch prompts directly to the governed fleet.

---

## 🧩 Project Structure

```
Warden/
├── demo.py                   # 6-scene interactive end-to-end demo
├── pyproject.toml            # Project metadata, CLI entrypoints, & dependencies
├── Dockerfile                # Multi-stage production container for Cloud Run
├── cloudbuild.yaml           # Automated Google Cloud Build configuration
├── scripts/
│   └── deploy_cloud_run.sh   # 1-click Google Cloud Run deployment script
├── warden/
│   ├── cli.py                # Operator CLI binary (`warden`)
│   ├── fleet.py              # ADK multi-agent hierarchy & runtime setup
│   ├── server.py             # FastAPI operator control plane & dashboard
│   ├── templates/
│   │   └── dashboard.html    # Modern real-time operator web dashboard
│   ├── security/
│   │   └── redteam.py        # 5-vector adversarial penetration test suite
│   ├── workflows.py          # Durable workflow state and Cloud Tasks resume lifecycle
│   ├── workflow_context.py   # Per-invocation approval/run metadata
│   ├── ledger/
│   │   ├── chain.py          # Cryptographic SHA-256 hash chain and verification
│   │   └── store.py          # MemoryLedger & transactional FirestoreLedger
│   ├── policy/
│   │   ├── engine.py         # Pure zero-trust policy evaluation
│   │   ├── approvals.py      # Approval store & operator decision protocol
│   │   ├── plugin.py         # Google ADK BasePlugin interceptor
│   │   └── policy.yaml       # Complete 47-tool declarative fleet governance rules
│   └── tools/
│       ├── definitions.py    # Infrastructure backend protocol & schemas
│       ├── factory.py        # ADK FunctionTool & McpToolset factory
│       ├── mock_provider.py  # Offline deterministic cloud simulation
│       └── manifold_bridge.py# Direct REST & MCP compute backend bridge
└── tests/
    ├── test_chain.py         # Hash chain tamper-evidence unit tests
    ├── test_fleet.py         # Multi-agent & ADK plugin integration tests
    ├── test_mcp_bridge.py    # MCP dynamic tool discovery & privilege tests
    ├── test_policy.py        # Zero-trust policy evaluation tests
    ├── test_redteam.py       # Adversarial penetration test verification
    ├── test_server.py        # Operator API endpoint tests
    └── test_workflows.py     # Workflow persistence and resume-state tests
```

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone and enter the repository
git clone https://github.com/Somnora/Warden.git
cd warden

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
uv pip install -e .
```

### 2. Run the Full Test Suite

```bash
pytest
```
```
============================== 54 passed in 1.29s ==============================
```

### 3. Run the Adversarial Red-Team Benchmark

```bash
warden redteam
```

### 4. Run the Live End-to-End Demo

```bash
python demo.py
```

### 5. Launch the Operator Control Plane & Web Dashboard

```bash
warden server --port 8000
```
Open **`http://localhost:8000`** in your browser to view the real-time Glassmorphism Dashboard.

### Desktop app (no terminal or browser URL)

The desktop launcher starts Warden on a private loopback port and opens the
dashboard in a native app window. It defaults to safe `mock` mode; live Cloud
Run settings remain opt-in through the existing environment variables.

```bash
# macOS (Apple Silicon): produces dist/Warden-macOS-arm64.dmg
bash scripts/build_macos_dmg.sh

# Windows: produces dist/Warden.exe
powershell -ExecutionPolicy Bypass -File scripts/build_windows.ps1
```

Tagged GitHub releases build both artifacts automatically. These packages are
unsigned until an Apple Developer ID and Windows code-signing certificate are
configured, so Gatekeeper or SmartScreen may show a first-launch warning.

---

## ☁️ Deploy to Google Cloud Run

Deploy Warden to Google Cloud in one command:

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_REGION="us-central1"
# The default deploy is the safe offline mock demo. Set live mode only when
# the Manifold execution backend and its credentials are configured.
export WARDEN_MODE="mock"

./scripts/deploy_cloud_run.sh
```

The service is deployed as a private Cloud Run service; grant the intended
operators `roles/run.invoker` rather than exposing approval controls publicly.
In `live` mode, Firestore stores audit, approval, and workflow state while
Cloud Tasks resumes approved work using an OIDC service-account identity.
The deploy script creates a dedicated `warden-runtime` service account by
default and grants it only `roles/datastore.user` and
`roles/cloudtasks.enqueuer`; set `WARDEN_RUNTIME_SERVICE_ACCOUNT` to override it.
Set `WARDEN_MODEL` to override the default `gemini-3.7-flash` model identifier.
For the private live service, set `WARDEN_ID_TOKEN` to a Google identity token
whose audience is the Cloud Run service URL before using the CLI. Local/mock
mode needs no token and accepts `--approver` only as a local display identity.

---

## 📜 Open-Source Disclosure

In compliance with hackathon rules:
- **Warden** is a newly developed codebase built during the August 2026 hackathon submission period.
- Warden incorporates and interfaces with **Manifold** as an external, disclosed MIT open-source dependency providing the underlying GPU lifecycle execution layer.
