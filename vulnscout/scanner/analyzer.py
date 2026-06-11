from __future__ import annotations

import json
import re
from typing import Any

import httpx
from openai import OpenAI

from openai import OpenAI

from vulnscout.core.config import settings

# ── Few-shot vulnerability templates ───────────────────────────────────

_FEW_SHOT_EXAMPLES: dict[str, list[dict[str, str]]] = {
    "python": [
        {
            "role": "user",
            "content": (
                'Find security vulnerabilities in this Python code:\n\n'
                '```python\n'
                'def login(username, password):\n'
                '    query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"\n'
                '    cursor.execute(query)\n'
                '    return cursor.fetchone()\n'
                '```'
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "vulnerabilities": [
                    {
                        "cwe_id": "CWE-89",
                        "severity": "critical",
                        "title": "SQL Injection",
                        "description": (
                            "User input is directly interpolated into the SQL query, "
                            "allowing attackers to inject arbitrary SQL commands."
                        ),
                        "line_start": 3,
                        "line_end": 3,
                        "confidence": 95,
                    }
                ]
            }),
        },
    ],
    "javascript": [
        {
            "role": "user",
            "content": (
                'Find security vulnerabilities in this JavaScript code:\n\n'
                '```javascript\n'
                'app.get("/user", (req, res) => {\n'
                '  const name = req.query.name;\n'
                '  res.send("<h1>Hello " + name + "</h1>");\n'
                '});\n'
                '```'
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "vulnerabilities": [
                    {
                        "cwe_id": "CWE-79",
                        "severity": "high",
                        "title": "Cross-Site Scripting (XSS)",
                        "description": (
                            "User input is directly concatenated into HTML without sanitization, "
                            "allowing injection of arbitrary JavaScript."
                        ),
                        "line_start": 3,
                        "line_end": 3,
                        "confidence": 95,
                    }
                ]
            }),
        },
    ],
}


# ── Vulnerability patterns (Tier 1: Rule pre-filter) ──────────────────

_DANGEROUS_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "python": [
        {
            "pattern": r"(?i)(password|secret|api_key|token)\s*=\s*['\"][^'\"]+['\"]",
            "cwe": "CWE-798",
            "severity": "high",
            "title": "Hardcoded Credential",
        },
        {
            "pattern": r"eval\s*\(",
            "cwe": "CWE-95",
            "severity": "critical",
            "title": "Code Injection via eval()",
        },
        {
            "pattern": r"os\.system\s*\(",
            "cwe": "CWE-78",
            "severity": "high",
            "title": "OS Command Injection",
        },
        {
            "pattern": r"subprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True",
            "cwe": "CWE-78",
            "severity": "high",
            "title": "OS Command Injection (shell=True)",
        },
        {
            "pattern": r"pickle\.(loads|load)\s*\(",
            "cwe": "CWE-502",
            "severity": "high",
            "title": "Insecure Deserialization (pickle)",
        },
        {
            "pattern": r"flask\.render_template_string\s*\(",
            "cwe": "CWE-1336",
            "severity": "high",
            "title": "Server-Side Template Injection",
        },
    ],
    "javascript": [
        {
            "pattern": r"(?i)(password|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            "cwe": "CWE-798",
            "severity": "high",
            "title": "Hardcoded Credential",
        },
        {
            "pattern": r"eval\s*\(",
            "cwe": "CWE-95",
            "severity": "critical",
            "title": "Code Injection via eval()",
        },
        {
            "pattern": r"new\s+Function\s*\(",
            "cwe": "CWE-94",
            "severity": "critical",
            "title": "Code Injection via Function()",
        },
    ],
    "java": [
        {
            "pattern": r"(?i)(password|secret|apiKey|token)\s*=\s*['\"][^'\"]+['\"]",
            "cwe": "CWE-798",
            "severity": "high",
            "title": "Hardcoded Credential",
        },
        {
            "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            "cwe": "CWE-78",
            "severity": "high",
            "title": "OS Command Injection",
        },
    ],
    "cpp": [
        {
            "pattern": r"strcpy\s*\(",
            "cwe": "CWE-121",
            "severity": "critical",
            "title": "Buffer Overflow (strcpy)",
        },
        {
            "pattern": r"sprintf\s*\(",
            "cwe": "CWE-120",
            "severity": "high",
            "title": "Buffer Overflow (sprintf)",
        },
        {
            "pattern": r"gets\s*\(",
            "cwe": "CWE-242",
            "severity": "critical",
            "title": "Unsafe gets() usage",
        },
    ],
}


def _rule_check(file_path: str, code: str, language: str) -> list[dict]:
    """Tier 1: Rule-based pre-filtering."""
    findings = []
    patterns = _DANGEROUS_PATTERNS.get(language, [])
    lines = code.split("\n")
    for p in patterns:
        for i, line in enumerate(lines):
            if re.search(p["pattern"], line):
                findings.append({
                    "cwe_id": p["cwe"],
                    "severity": p["severity"],
                    "title": p["title"],
                    "description": f"Pattern detected: {p['pattern']}",
                    "line_start": i + 1,
                    "line_end": i + 1,
                    "confidence": 80,
                    "file_path": file_path,
                })
    return findings


def _build_zero_shot_prompt(code: str, language: str) -> str:
    """Build a zero-shot prompt for vulnerability analysis."""
    return (
        f"You are a security code audit expert. Analyze the following {language} code "
        f"for security vulnerabilities. Return results as a JSON object with a "
        f'"vulnerabilities" array. Each vulnerability has: cwe_id, severity '
        f'(critical/high/medium/low), title, description, line_start, line_end, confidence (0-100).\n\n'
        f"If no vulnerabilities found, return {{\"vulnerabilities\": []}}.\n\n"
        f"```{language}\n{code}\n```"
    )


def _build_fix_prompt(code: str, vulnerability: dict, language: str) -> str:
    """Build a prompt for generating a fix."""
    return (
        f"Generate a secure fix for the following vulnerability in {language} code.\n\n"
        f"Vulnerability: {vulnerability.get('title', 'Unknown')} ({vulnerability.get('cwe_id', 'N/A')})\n"
        f"Description: {vulnerability.get('description', '')}\n"
        f"Lines {vulnerability.get('line_start', '?')}-{vulnerability.get('line_end', '?')}\n\n"
        f"```{language}\n{code}\n```\n\n"
        f"Return ONLY the fixed code wrapped in ``` fences. Replace ONLY the vulnerable "
        f"lines. Keep the rest of the code identical."
    )


class Analyzer:
    """Three-tier vulnerability analyzer."""

    def __init__(self):
        self._model_available: bool | None = None

    def _check_model(self) -> bool:
        """Quick-check if model API is reachable (no timeout hang)."""
        if self._model_available is not None:
            return self._model_available
        try:
            import httpx
            r = httpx.get(f"{settings.openai_base_url}/../api/tags", timeout=2.0)
            self._model_available = r.status_code == 200
        except Exception:
            self._model_available = False
        return self._model_available

    def analyze(
        self,
        file_path: str,
        code: str,
        language: str,
        model: str | None = None,
    ) -> list[dict]:
        """Run all three tiers and return merged vulnerabilities."""
        model = model or settings.model_name

        # Tier 1: Rule pre-filter
        rule_findings = _rule_check(file_path, code, language)

        # Tier 2 & 3: Model-based analysis
        model_findings = []
        if self._check_model():
            if not hasattr(self, 'client'):
                self.client = OpenAI(
                    base_url=settings.openai_base_url,
                    api_key=settings.openai_api_key,
                    timeout=10.0,
                    max_retries=0,
                )
            model_findings = self._model_analyze(code, language, model)

        # Merge: rule takes priority for pattern-based, model for everything else
        seen_titles = {f["title"] for f in rule_findings}
        merged = list(rule_findings)
        for mf in model_findings:
            # Validate required fields; skip malformed findings
            if not isinstance(mf, dict) or "title" not in mf:
                continue
            # Normalize numeric fields (model may return strings)
            for int_field in ("line_start", "line_end", "confidence"):
                if int_field in mf:
                    try:
                        mf[int_field] = int(mf[int_field])
                    except (TypeError, ValueError):
                        mf[int_field] = 0
            if mf["title"] not in seen_titles:
                mf["file_path"] = file_path
                merged.append(mf)
                seen_titles.add(mf["title"])

        return merged

    def _model_analyze(
        self, code: str, language: str, model: str
    ) -> list[dict]:
        """Tier 2 (zero-shot) + Tier 3 (few-shot) analysis."""
        messages = []

        # Add few-shot examples if available
        examples = _FEW_SHOT_EXAMPLES.get(language, [])
        messages.extend(examples)

        # Add zero-shot prompt
        messages.append({
            "role": "user",
            "content": _build_zero_shot_prompt(code, language),
        })

        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                max_tokens=2048,
            )
            content = response.choices[0].message.content
            if not content:
                return []
            result = json.loads(content)
            vulns = result.get("vulnerabilities", [])
            # Ensure each vuln has required fields
            for v in vulns:
                v.setdefault("title", "Unknown Vulnerability")
                v.setdefault("severity", "medium")
                v.setdefault("cwe_id", "unknown")
                v.setdefault("description", "")
                v.setdefault("line_start", 1)
                v.setdefault("line_end", 1)
                v.setdefault("confidence", 50)
            return vulns
        except json.JSONDecodeError:
            return []
        except Exception:
            return []

    def generate_fix(
        self,
        code: str,
        vulnerability: dict,
        language: str,
        model: str | None = None,
    ) -> str | None:
        """Generate a fix patch for a vulnerability."""
        if not self._check_model():
            return None

        model = model or settings.model_name

        if not hasattr(self, 'client'):
            self.client = OpenAI(
                base_url=settings.openai_base_url,
                api_key=settings.openai_api_key,
                timeout=10.0,
                max_retries=0,
            )

        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": _build_fix_prompt(code, vulnerability, language),
                    }
                ],
                temperature=0.1,
                max_tokens=4096,
            )
            content = response.choices[0].message.content
            # Extract code from markdown fences
            match = re.search(r"```(?:\w+)?\n(.*?)\n```", content, re.DOTALL)
            if match:
                return match.group(1)
            return content
        except Exception:
            return None
