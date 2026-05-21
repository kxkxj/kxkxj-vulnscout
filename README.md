# VulnScout — AI-Powered Vulnerability Code Audit Assistant

<p align="right">
  <a href="README-zh.md">简体中文</a>
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

VulnScout scans source code for security vulnerabilities using locally deployed
DeepSeek-Coder AI models via [Ollama](https://ollama.com). Supports Web UI and CLI,
with automatic GPU adaptation.

## Platform Support

| Platform | CLI | Web UI | Docker |
|----------|:---:|:------:|:------:|
| Linux | ✅ | ✅ | ✅ |
| Windows | ✅ | ✅ | ⚠️ (WSL2) |

> Windows: CLI and Web UI are fully supported. For Docker, use WSL2 backend.

## Features

- **Multi-language support**: Python, JavaScript/TypeScript, Java, C/C++
- **Three-tier detection**: Rule pre-filter + zero-shot AI + few-shot templates
- **Auto-fix generation**: Unified diff patches for each vulnerability
- **Web UI**: Interactive dashboard with diff viewer and severity breakdown
- **CLI**: Terminal-first workflow with SARIF/JSON/Markdown reports
- **Privacy-first**: All processing runs locally on your machine
- **Auto hardware detection**: Automatically selects optimal model for your GPU

## Quick Start

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.com) — handles model serving and GPU acceleration
- (Optional) NVIDIA GPU with 8GB+ VRAM for GPU mode

### 1. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Install VulnScout

```bash
git clone https://github.com/yujh129/vulnscout.git
cd vulnscout
pip install -e ".[dev]"
```

### 3. Pull the AI model

```bash
vulnscout model download
# or: ollama pull deepseek-coder:1.3b
```

### 4. Run a scan

```bash
vulnscout scan ./my-project
vulnscout scan https://github.com/user/repo
vulnscout scan https://github.com/yujh129/AI-Desktop-Pet

# Export formats
vulnscout scan ./my-project --format sarif --output report.sarif
vulnscout scan ./my-project --format markdown --output report.md
```

### Optional: Start the Web UI

**Option A — One port (recommended):** Build frontend once, then API + UI on :8000

```bash
cd frontend
npm install
npm run build
cd ..
uvicorn vulnscout.main:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

**Option B — Two ports (dev mode):** No build needed, UI auto-reloads

```bash
# Terminal 1: API server
uvicorn vulnscout.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Frontend dev server
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

### Docker

```bash
docker compose up -d
docker compose exec api vulnscout model download
docker compose exec api vulnscout scan /data
# Open http://localhost:3000
```

## CLI Reference

```
vulnscout scan <path>              Scan a local path, GitHub URL, or ZIP file
vulnscout scan <path> --format json|sarif|markdown
vulnscout scan <path> --auto-fix   Auto-generate fix patches
vulnscout doctor                   Diagnose environment
vulnscout model list               List available AI models
vulnscout model download <name>    Pull an AI model via Ollama
vulnscout model use <name>         Switch to a different model
vulnscout model status             Show current model & provider
vulnscout config init              Create configuration file
vulnscout config show              Display all current settings
vulnscout patch apply <vuln-id>    Apply a fix patch
vulnscout patch apply-all <scan>   Apply all patches for a scan
vulnscout github issue <scan-id>   Create GitHub issues for vulnerabilities
vulnscout github pr <scan-id>      Create a PR with auto-generated fixes
vulnscout uninstall                Completely remove VulnScout
```

## Model Configuration

Three ways to run AI analysis:

### Option 1: Local Ollama (default)
```bash
vulnscout config set MODEL_PROVIDER ollama
vulnscout config set MODEL_NAME deepseek-coder:1.3b
vulnscout model download
vulnscout scan ./my-project
```

### Option 2: OpenAI API (cloud)
```bash
vulnscout config set MODEL_PROVIDER openai
vulnscout config set MODEL_NAME gpt-4o-mini
vulnscout config set OPENAI_API_KEY sk-xxxxxxxxxxxxxxxxxxxx
vulnscout scan ./my-project
```

### Option 3: Any OpenAI-compatible API (cloud)
```bash
vulnscout config set MODEL_PROVIDER custom
vulnscout config set MODEL_NAME deepseek-chat
vulnscout config set OPENAI_BASE_URL https://api.deepseek.com/v1
vulnscout config set OPENAI_API_KEY sk-xxxxxxxxxxxxxxxxxxxx
vulnscout scan ./my-project
```

## GitHub Integration

```bash
vulnscout config set GITHUB_TOKEN ghp_xxxxxxxxxxxxxxxxxxxx
vulnscout github issue <scan-id>
vulnscout github pr <scan-id>
```

## How It Works

1. **Code acquisition**: Local directory, GitHub clone, or ZIP upload
2. **Language detection**: Auto-detects Python/JS/TS/Java/C/C++
3. **AST chunking**: Splits code into function-level units via tree-sitter
4. **Three-tier analysis**: Regex rules → Zero-shot AI → Few-shot examples
5. **Fix generation**: AI generates unified diff patches
6. **Reporting**: JSON, SARIF 2.1.0, or Markdown

## License

MIT

---

*Built with [Vibe Coding](https://github.com/yujh129/vulnscout) using [pi](https://github.com/earendil-works/pi-coding-agent) — an AI-powered coding agent.*
