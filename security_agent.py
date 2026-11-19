import json
import os
import subprocess
import sys
from google import genai
from google.genai import types

# ---------------------------------------------------------------------------
# Global Execution Trace Store
# ---------------------------------------------------------------------------
AGENT_TRACES = []

# ---------------------------------------------------------------------------
# 1. Tool Definitions
# ---------------------------------------------------------------------------

def run_semgrep_scan(target_dir: str = ".") -> str:
    """
    Runs Semgrep rules on the repository and returns structured JSON findings.
    
    Args:
        target_dir: The directory path to scan (defaults to '.').
    """
    print(f"\n[TOOL EXECUTION] 🛠️  Running Semgrep scan on '{target_dir}'...")
    cmd = [
        "semgrep", "scan",
        "--config=auto",
        "--json",
        "--quiet",
        target_dir
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        data = json.loads(result.stdout)
        
        findings = []
        for match in data.get("results", []):
            findings.append({
                "check_id": match.get("check_id"),
                "path": match.get("path"),
                "start_line": match.get("start", {}).get("line"),
                "end_line": match.get("end", {}).get("line"),
                "message": match.get("extra", {}).get("message"),
                "severity": match.get("extra", {}).get("severity"),
            })
        
        summary_finding = f"Discovered {len(findings)} potential security issue(s)."
        print(f"[TOOL RESULT] ✅ {summary_finding}")
        
        AGENT_TRACES.append({
            "step": len(AGENT_TRACES) + 1,
            "tool": "run_semgrep_scan",
            "action": f"Executed automated Semgrep rules on directory '{target_dir}'.",
            "args": {"target_dir": target_dir},
            "observation": summary_finding
        })

        return json.dumps(findings, indent=2)
    except Exception as e:
        err_msg = f"Error running Semgrep: {str(e)}"
        print(f"[TOOL ERROR] ❌ {err_msg}")
        AGENT_TRACES.append({
            "step": len(AGENT_TRACES) + 1,
            "tool": "run_semgrep_scan",
            "action": f"Attempted Semgrep scan on '{target_dir}'.",
            "args": {"target_dir": target_dir},
            "observation": err_msg
        })
        return err_msg


def read_file(path: str, start_line: int, end_line: int) -> str:
    """
    Reads a specific range of lines from a source file for context analysis.
    
    Args:
        path: Relative file path to read (e.g., 'app/vulnerable_app.py').
        start_line: The exact starting line number determined by the agent.
        end_line: The exact ending line number determined by the agent.
    """
    print(f"\n[TOOL EXECUTION] 🛠️  Reading '{path}' (lines {start_line}-{end_line})...")
    if not os.path.exists(path):
        err_msg = f"File '{path}' not found."
        print(f"[TOOL ERROR] ❌ {err_msg}")
        AGENT_TRACES.append({
            "step": len(AGENT_TRACES) + 1,
            "tool": "read_file",
            "action": f"Attempted to read '{path}' (lines {start_line}-{end_line}).",
            "args": {"path": path, "start_line": start_line, "end_line": end_line},
            "observation": err_msg
        })
        return err_msg
    
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        actual_start = max(1, start_line)
        actual_end = min(total_lines, end_line)

        selected = lines[actual_start - 1 : actual_end]
        numbered = [f"{actual_start + i}: {line}" for i, line in enumerate(selected)]
        content = "".join(numbered)
        
        obs = f"Retrieved lines {actual_start}-{actual_end} ({len(selected)} lines total)."
        print(f"[TOOL RESULT] ✅ {obs}")

        AGENT_TRACES.append({
            "step": len(AGENT_TRACES) + 1,
            "tool": "read_file",
            "action": f"Inspected '{path}' to analyze input data flow.",
            "args": {"path": path, "start_line": actual_start, "end_line": actual_end},
            "observation": obs
        })

        return content
    except Exception as e:
        err_msg = f"Error reading file {path}: {str(e)}"
        print(f"[TOOL ERROR] ❌ {err_msg}")
        AGENT_TRACES.append({
            "step": len(AGENT_TRACES) + 1,
            "tool": "read_file",
            "action": f"Read attempt on '{path}'.",
            "args": {"path": path, "start_line": start_line, "end_line": end_line},
            "observation": err_msg
        })
        return err_msg


def list_files(directory: str = ".") -> str:
    """
    Lists files in the project to understand repository layout.
    
    Args:
        directory: The root directory to list files from.
    """
    print(f"\n[TOOL EXECUTION] 🛠️  Listing files in '{directory}'...")
    file_list = []
    for root, dirs, files in os.walk(directory):
        if ".git" in root or "venv" in root or "__pycache__" in root:
            continue
        for file in files:
            file_list.append(os.path.relpath(os.path.join(root, file), directory))
    
    obs = f"Found {len(file_list)} files in repository."
    print(f"[TOOL RESULT] ✅ {obs}")

    AGENT_TRACES.append({
        "step": len(AGENT_TRACES) + 1,
        "tool": "list_files",
        "action": f"Surveyed repository structure under '{directory}'.",
        "args": {"directory": directory},
        "observation": obs
    })

    return "\n".join(file_list[:100])


# ---------------------------------------------------------------------------
# 2. Agent Execution
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an automated AppSec Senior Security Engineer Agent.
Your process:
1. First, call `run_semgrep_scan` to discover potential security issues.
2. Next, for flagged issues, call `read_file` with dynamic start_line and end_line values to inspect code context.
3. Determine whether each finding is a true positive or false positive.
4. Structure your response in clean Markdown. DO NOT include any introductory or concluding conversational filler (e.g. "A comprehensive security review..."). Start your response DIRECTLY with the heading `## 📊 Executive Summary Table`.

## 📊 Executive Summary Table
| Severity | Vulnerability | Description | Location | Status | Action Required |
| :--- | :--- | :--- | :--- | :--- | :--- |
| High / Med / Low | Issue Name | Brief 1-sentence risk summary | `path/file.py:line` | Confirmed / False Positive | Yes / No |

## 📋 Detailed Findings & Remediations
For each verified vulnerability:
- **Severity & Impact**
- **Location:** `file:line`
- **Root Cause Analysis**
- **Remediation Code Snippet**

### Dismissed False Positives
List any dismissed items with justifications.
"""

def run_agent(api_key: str):
    client = genai.Client(api_key=api_key)
    
    print("=" * 70)
    print("🤖 Starting AI Security Agent...")
    print("=" * 70)

    prompt = (
        "Perform a complete security review of this project. "
        "Use your tools to scan for vulnerabilities, inspect code files for context, "
        "and produce a final security report starting directly with the executive summary table."
    )

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            tools=[run_semgrep_scan, read_file, list_files],
        )
    )

    llm_text = response.text if response.text else "_No report content generated._"

    # Strip out any conversational intro line appearing before the summary table
    if "## 📊 Executive Summary Table" in llm_text:
        llm_text = "## 📊 Executive Summary Table" + llm_text.split("## 📊 Executive Summary Table", 1)[1]

    # Separate Summary Table from Detailed Findings to position Traces in between
    summary_part = ""
    detailed_part = ""

    if "## 📋 Detailed Findings & Remediations" in llm_text:
        parts = llm_text.split("## 📋 Detailed Findings & Remediations", 1)
        summary_part = parts[0].strip()
        detailed_part = "## 📋 Detailed Findings & Remediations" + parts[1]
    else:
        summary_part = llm_text.strip()
        detailed_part = ""

    # ---------------------------------------------------------------------------
    # 3. Assemble Final Report:
    #    1. Header & Summary Table
    #    2. Agent Reasoning & Tool Traces
    #    3. Detailed Findings & Remediations
    # ---------------------------------------------------------------------------
    final_output = "# 🛡️ Security Audit Report\n\n"
    final_output += summary_part + "\n\n---\n\n"

    final_output += "## 🔍 Agent Reasoning & Tool Traces\n\n"
    if AGENT_TRACES:
        for t in AGENT_TRACES:
            final_output += f"### Step {t['step']}: `{t['tool']}`\n"
            final_output += f"- **Action:** {t['action']}\n"
            final_output += f"- **Observation:** {t['observation']}\n"
            final_output += f"- **Arguments Provided:**\n```json\n{json.dumps(t['args'], indent=2)}\n```\n\n"
    else:
        final_output += "_No tool calls recorded._\n\n"

    final_output += "---\n\n"

    if detailed_part:
        final_output += detailed_part + "\n"

    print("\n" + "=" * 70)
    print("📝 GENERATED REPORT PREVIEW")
    print("=" * 70)
    print(final_output)

    with open("security_report.md", "w", encoding="utf-8") as f:
        f.write(final_output)

if __name__ == "__main__":
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_api_key:
        print("❌ Error: GEMINI_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    run_agent(gemini_api_key)
