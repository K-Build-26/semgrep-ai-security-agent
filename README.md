# 🛡️ AI Security Agent with Semgrep & Gemini

An autonomous Application Security Agent built with **Semgrep**, **Google Gemini**, and **GitHub Actions**. It scans source code for vulnerabilities, investigates code context to verify true positives, and produces an actionable remediation report with reasoning traces.

## 🔄 Agent Workflow

1. **Trigger / Scan**: The agent invokes Semgrep using the `run_semgrep_scan` tool.
2. **Context Investigation**: Using the file paths and line numbers flagged by Semgrep, the agent calls helper tools (`read_file`, `list_files`) to inspect the surrounding code and verify vulnerabilities
3. **Reasoning Traces**: The agent logs why it chose a specific tool, the exact dynamic parameters passed (such as target line ranges), and a concise observation of what it discovered during that step.
4. **Report & Fixes**: The agent compiles the entire assessment into `security_report.md` and publishes it in GitHub:
   - **GitHub Actions Step Summary**: Published on every run (pushes and PRs) for instant review in the Actions tab.
   - **Pull Request Comments**: When triggered by a Pull Request, the bot automatically posts the complete report as a comment on the PR conversation for code reviewers.
---

## 🚀 Quick Start (Local Reproduction)

### Prerequisites
- Python 3.10+
- A [Google AI Studio Gemini API Key](https://aistudio.google.com/)

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
cd <YOUR_REPO_NAME>

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment Variable
```bash
export GEMINI_API_KEY="your-api-key-here"
```

### 3. Run the Agent
```bash
python security_agent.py
```

## ⚙️ Running in GitHub Actions

To run this automatically on your own fork or repository:

1. Fork or push this repository to GitHub.
2. Go to **Settings** > **Secrets and variables** > **Actions** > **New repository secret**.
3. **Name:** `GEMINI_API_KEY`
4. **Value:** Paste your Gemini API key.
5. Push a commit or create a PR to trigger the `.github/workflows/security-agent.yml` workflow.

---

## 📂 Repository Structure

```text
├── .github/workflows/
│   └── security-agent.yml   # GitHub Actions automation
├── app/
│   └── vulnerable_app.py    # Test codebase with intentional vulnerabilities
├── security_agent.py        # Core agent loop and tool definitions
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
