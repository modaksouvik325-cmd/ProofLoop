# ◈ ProofLoop

### AI Coding Agent · Independent Verification · Evidence-First Development

ProofLoop is an AI-powered coding agent designed around one principle:

**Code is not trusted until it is independently verified.**

It generates code, evaluates implementations, executes approved test cases, detects failures, attempts repairs, and records verification evidence.

## 🚀 Features

- **AI Code Generation** — Generate Python implementations from natural-language instructions.
- **Independent Verification** — Run approved test cases against generated code.
- **Automated Repair** — Detect failed tests, repair implementations, and verify again.
- **Security Analysis** — Analyze code for potential vulnerabilities and risky patterns.
- **Security Scanning** — Integrate Bandit and pip-audit.
- **Evidence Records** — Preserve build results, verification status, and repair attempts.
- **Private Workspaces** — Google authentication and user-specific local chat storage.
- **Multiple Model Providers** — Support for Gemini and local Ollama models.

## 🏗️ Architecture

```text
User Request
     |
     v
AI Code Generator
     |
     v
Generated Implementation
     |
     v
Human Test Approval
     |
     v
Independent Verifier
     |
     +------ Tests Pass ------> Verified Build
     |
     +------ Tests Fail ------> Repair Engine
                                      |
                                      v
                               Re-verification
                                      |
                                      v
                                Evidence Record
```

## 🛠️ Technology Stack

- Python
- Streamlit
- Google Gemini API
- Ollama
- Bandit
- pip-audit
- SQLite
- Git

## ⚙️ Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ProofLoop.git
cd ProofLoop
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file using the required configuration:

```env
MODEL_PROVIDER=gemini
GEMINI_API_KEY=your_api_key
GEMINI_MODEL=your_supported_model
```

For local Ollama development, configure the provider and model accordingly.

Never commit API keys or OAuth credentials.

### 5. Run ProofLoop

```bash
streamlit run app.py
```

## 🔬 Verification Philosophy

A successful AI response is not proof of correctness.

ProofLoop distinguishes between:
- Generated code
- Human-approved test cases
- Independently executed verification
- Repaired implementations
- Recorded evidence

A VERIFIED result means all approved test cases passed. It does not guarantee correctness beyond those tests.

## ⚠️ Security Notice

**Research prototype — not production-hardened.**

The current execution engine runs generated code locally with the operating system user's permissions. It is not a secure sandbox.

Do not expose code execution to untrusted users or deploy it as a public execution service without implementing proper isolation and resource controls.

## 🎯 Project Vision

Build AI systems whose outputs can be inspected, challenged, tested, and supported by evidence rather than accepted on trust.

---

**ProofLoop — Generate. Challenge. Verify.**