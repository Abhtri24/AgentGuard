# AgentGuard 🛡️

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture: Dual--Engine](https://img.shields.io/badge/Architecture-ADK%20%2B%20CrewAI-purple.svg)](#architecture)
[![Coverage: OWASP Top 10 for LLM](https://img.shields.io/badge/Coverage-OWASP%20LLM-red.svg)](#attack-vectors)

**AgentGuard** is an automated, adaptive red-teaming and vulnerability assessment framework for AI agents and LLM-powered applications. 

Unlike conventional static prompts or single-shot fuzzers, AgentGuard mounts **multi-turn, goal-directed adversarial attacks** against running agents, dynamically escalating through defensive refusals. When vulnerabilities are triggered, AgentGuard uses semantic code retrieval to map compromises back to specific functions in your codebase and generates production-ready remediation patches.

---

## ⚡ Key Capabilities

- 🎯 **Adaptive Multi-Turn Exploitation:** Attacker agents maintain conversational context, probe for edge cases, and adaptively pivot when your agent attempts defensive refusals.
- 👁️ **Zero-False-Positive Oracles:** Detects compromises using cryptographic canaries, LLM judge verification, and live tool execution interception via `@watch`.
- 🔍 **AST-Aware Semantic Remediation:** Indexes your target repository with ChromaDB vector search to match exploit traces directly to the vulnerable function and suggest exact code fixes.
- 🌐 **Provider-Agnostic (LiteLLM):** Red-team with ultra-fast free-tier models (Groq, Cohere, Google Gemini) or commercial engines (OpenAI, Anthropic), or run fully offline with local Ollama models.
- ⏱️ **Resilient Rate Limiting & Backoff:** Built-in token-bucket rate limiting and intelligent exponential backoff prevent quota lockouts during intensive scan runs.
- 🔒 **Security-by-Design Architecture:** The dynamic attacker writes execution traces to `findings.json` and exits; the analysis reporter operates offline without socket or network permissions to the target.

---

## 🏗️ Architecture

AgentGuard splits responsibilities between two specialized engines separated by a strict data boundary:

```
+-------------------------------------------------------------------------+
|                           TARGET AI AGENT                               |
|        (@expose endpoint  <--->  @watch tool execution monitor)         |
+-------------------------------------------------------------------------+
                                   ▲   │
       Adversarial Probes (HTTP)   │   │  Responses & Tool Side-Effects
                                   │   ▼
+-------------------------------------------------------------------------+
|                      PHASE 1: DYNAMIC RED TEAMER                        |
|       Adaptive multi-turn playbooks: prompt leak, RCE, injection        |
+-------------------------------------------------------------------------+
                                       │
                                       ▼ writes
                                findings.json
                                       │
                                       ▼ reads (Air-gapped)
+-------------------------------------------------------------------------+
|                      PHASE 2: OFFLINE AUDITOR                           |
|       ChromaDB Semantic Code Search  +  CrewAI Remediation Agent        |
+-------------------------------------------------------------------------+
                                       │
                                       ▼ outputs
                                   report.md
```

1. **ADK Dynamic Attacker (`agentguard/attackers.py`):** Drives stateful adversarial sessions over HTTP against your live agent application.
2. **`findings.json` (Boundary):** Contains raw multi-turn conversation transcripts, tool execution traces, and verification oracle verdicts.
3. **CrewAI Reporter (`agentguard/reporters.py`):** Reads `findings.json` and local source code chunks, synthesizing a CVSS-rated Markdown vulnerability audit report without opening network connections to the target.

---

## 🚀 3-Minute Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/<your-username>/agentguard.git
cd agentguard

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install in editable mode
pip install -e .
```

### 2. Configure API Keys

AgentGuard supports free-tier providers like **Groq**, **Cohere**, and **Google Gemini**:

```bash
cp .env.example .env
```

Open `.env` and set your key(s):
```env
GROQ_API_KEY=your_groq_api_key
COHERE_API_KEY=your_cohere_api_key

AGENTGUARD_ATTACKER_MODEL=groq/openai/gpt-oss-20b
AGENTGUARD_REPORTER_MODEL=cohere/command-r-08-2024
```

### 3. Test a Vulnerable Sample Agent

Terminal 1 — Launch the included command injection sample agent:
```bash
uvicorn samples.unsafe_tool.app:app --host 127.0.0.1 --port 8000
```

Terminal 2 — Launch the AgentGuard red-team probe:
```bash
agentguard -v test samples/unsafe_tool --target-url http://127.0.0.1:8000 --max-probes 3
```

Check your directory: AgentGuard generates `findings.json` and a comprehensive `report.md` detailing the exploit path and code remediations!

---

## 🛠️ Instrumenting Your Own Agent

Instrumenting your agent requires just two decorators:

```python
from agentguard import expose, watch

# 1. Watch dangerous tools to intercept destructive arguments during testing
@watch
def run_command(command: str):
    import subprocess
    return subprocess.check_output(command, shell=True, text=True)

# 2. Expose your agent entrypoint for HTTP red-teaming
@expose
def chat(prompt: str, session_id: str = None) -> str:
    return my_agent_pipeline.query(prompt)
```

See the [User Manual](USER_MANUAL.md#5-instrumenting-your-own-agent) for full integration details.

---

## 📋 Attack Vectors Covered

AgentGuard includes playbooks aligned with the OWASP Top 10 for LLM Applications:

| Attack Category | Threat Description | Verification Oracle |
|---|---|---|
| `prompt_leak` | Coercing model to disclose system instructions or planted canaries | Canary & String Leak Oracle |
| `insecure_tool` | Shell command injection, SQL injection, unauthorized API calls | Tool Argument Interception (`@watch`) |
| `prompt_injection` | Overriding core safety instructions via direct/indirect jailbreaks | Multi-turn Judge Oracle |
| `data_exfiltration` | Coercing agent to transmit private user context to unauthorized URLs | Side-Effect URL & Payload Oracle |
| `privilege_escalation` | Bypassing authorization barriers to trigger administrative actions | Restricted Tool Call Oracle |
| `memory_poisoning` | Corrupting multi-turn conversational memory with malicious state | Context Verification Oracle |
| `hallucination` | Forcing false consensus or deceptive grounded reasoning | Factual Consistency Oracle |

---

## 📖 Documentation

For detailed guides, CLI commands, configuration options, and troubleshooting, read the **[AgentGuard User Manual](USER_MANUAL.md)**:

- [Installation & Virtual Environment Setup](USER_MANUAL.md#2-installation--setup)
- [Multi-Provider Configuration Guide](USER_MANUAL.md#3-configuring-llm-providers)
- [How to Instrument Custom Agents](USER_MANUAL.md#5-instrumenting-your-own-agent)
- [CLI Reference (`init`, `test`, `report`)](USER_MANUAL.md#6-cli-reference--commands)
- [Interpreting findings.json and report.md](USER_MANUAL.md#7-understanding-the-output-reports)
- [Vulnerable Sample Applications Guide](USER_MANUAL.md#4-quickstart-tutorial-run-a-sample-agent)
- [Troubleshooting & Rate Limiting Tips](USER_MANUAL.md#10-troubleshooting--faq)

---

## 🧪 Running Tests

To verify your installation and run the full test suite:

```bash
pytest
```

---

## 📄 License

AgentGuard is licensed under the [MIT License](LICENSE).
