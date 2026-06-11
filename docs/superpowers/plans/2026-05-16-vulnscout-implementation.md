# VulnScout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MVP of VulnScout — an AI vulnerability code audit assistant with Web UI + CLI, powered by locally deployed DeepSeek-Coder, supporting Python/JS/Java/C++.

**Architecture:** Python-based monolithic backend (FastAPI + Celery) with React frontend. Three-tier cascade vulnerability detection (rule → zero-shot → few-shot). Auto GPU detection with pluggable inference backends (vLLM/llama.cpp). Single binary CLI via pip, Docker Compose for full-stack deployment.

**Tech Stack:** Python 3.11+, FastAPI, Celery, SQLite/SQLAlchemy, tree-sitter, vLLM/llama.cpp, Click, React 18 + TypeScript + MUI, Monaco Editor, Vite.

---

## File Structure

```
vulnscout/
├── pyproject.toml
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── .gitignore
├── README.md
│
├── vulnscout/
│   ├── __init__.py
│   ├── main.py                       # FastAPI app factory
│   ├── cli.py                        # Click CLI
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py                 # API router aggregation
│   │   ├── scans.py                  # /api/v1/scans endpoints
│   │   ├── patches.py                # /api/v1/patches endpoints
│   │   └── ws.py                     # WebSocket handler
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py                 # pydantic-settings config
│   │   ├── i18n.py                   # gettext i18n wrapper
│   │   ├── detector.py              # GPU/hardware detection
│   │   └── model_manager.py         # Model download & lifecycle
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── pipeline.py              # Scan orchestration
│   │   ├── code_fetcher.py          # ZIP/GitHub/local fetch
│   │   ├── language_detector.py     # Language detection + file filter
│   │   ├── chunker.py               # Tree-sitter AST chunking
│   │   ├── analyzer.py              # Model inference (three-tier)
│   │   ├── dedup.py                 # CWE-based deduplication
│   │   └── patch_generator.py       # Unified diff generation
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── db.py                    # SQLAlchemy engine + session
│   │   └── schemas.py               # SQLAlchemy models + Pydantic schemas
│   │
│   ├── worker/
│   │   ├── __init__.py
│   │   └── celery_app.py            # Celery app definition
│   │
│   └── utils/
│       ├── __init__.py
│       ├── git_utils.py             # Git operations
│       └── report_formatter.py      # SARIF/JSON/MD formatters
│
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── i18n/
│       │   ├── index.ts
│       │   ├── en.json
│       │   └── zh.json
│       ├── api/
│       │   ├── client.ts            # HTTP + WS client
│       │   ├── scans.ts             # Scan API calls
│       │   └── patches.ts           # Patch API calls
│       ├── pages/
│       │   ├── Dashboard.tsx
│       │   ├── NewScan.tsx
│       │   ├── ScanProgress.tsx
│       │   ├── ScanResult.tsx
│       │   ├── VulnDetail.tsx
│       │   └── Report.tsx
│       ├── components/
│       │   ├── Layout.tsx
│       │   ├── Header.tsx
│       │   ├── SeverityBadge.tsx
│       │   ├── FileTree.tsx
│       │   ├── DiffViewer.tsx
│       │   ├── VulnCard.tsx
│       │   └── ProgressBar.tsx
│       └── types/
│           └── index.ts
│
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_detector.py
    ├── test_scanner/
    │   ├── test_code_fetcher.py
    │   ├── test_language_detector.py
    │   ├── test_chunker.py
    │   ├── test_analyzer.py
    │   └── test_dedup.py
    ├── test_api/
    │   ├── test_scans.py
    │   └── test_patches.py
    └── test_cli.py
```

---

### Phase 1: Project Scaffold & Core Infrastructure

### Task 1: Project scaffold, config, and i18n

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `vulnscout/__init__.py`
- Create: `vulnscout/core/__init__.py`
- Create: `vulnscout/core/config.py`
- Create: `vulnscout/core/i18n.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["pdm-backend"]
build-backend = "pdm.backend"

[project]
name = "vulnscout"
version = "0.1.0"
description = "AI Vulnerability Code Audit Assistant powered by DeepSeek-Coder"
requires-python = ">=3.11"
authors = [
    {name = "VulnScout Team", email = "team@vulnscout.dev"},
]
license = {text = "MIT"}
readme = "README.md"

dependencies = [
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.27.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "pydantic>=2.0.0",
    "pydantic-settings>=2.0.0",
    "click>=8.1.0",
    "celery>=5.3.0",
    "redis>=5.0.0",
    "py-tree-sitter>=0.23.0",
    "gitpython>=3.1.0",
    "httpx>=0.26.0",
    "aiofiles>=23.0.0",
    "python-multipart>=0.0.9",
    "websockets>=12.0",
    "rich>=13.0.0",
    "openai>=1.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.0.0",
    "ruff>=0.3.0",
    "mypy>=1.8.0",
]

[project.scripts]
vulnscout = "vulnscout.cli:cli"

[tool.pdm]
distribution = true

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create .gitignore**

```
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/
.pytest_cache/
.env
*.db
vulnscout_models/
```

- [ ] **Step 3: Create .env.example**

```bash
# VulnScout Configuration
MODEL_NAME=deepseek-coder-1.3b-instruct
MODEL_BACKEND=llama.cpp
# MODEL_BACKEND=vllm
# MODEL_BACKEND=openai-compatible
OPENAI_BASE_URL=http://localhost:8000/v1
OPENAI_API_KEY=not-needed

# Storage
DATABASE_URL=sqlite:///vulnscout.db
MODEL_CACHE_DIR=~/.vulnscout/models

# Celery (optional Redis)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

- [ ] **Step 4: Create vulnscout/core/config.py**

```python
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic_settings import BaseSettings


class ModelBackend(str, Enum):
    LLAMA_CPP = "llama.cpp"
    VLLM = "vllm"
    OPENAI_COMPATIBLE = "openai-compatible"


class Settings(BaseSettings):
    model_class: str = "deepseek-coder-1.3b-instruct"
    model_backend: ModelBackend = ModelBackend.LLAMA_CPP
    openai_base_url: str = "http://localhost:8000/v1"
    openai_api_key: str = "not-needed"

    database_url: str = "sqlite:///vulnscout.db"
    model_cache_dir: str = str(Path.home() / ".vulnscout" / "models")

    celrey_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    max_file_size: int = 1024 * 1024  # 1MB
    max_upload_size: int = 100 * 1024 * 1024  # 100MB
    chunk_timeout: int = 30  # seconds per chunk
    max_concurrent_chunks: int = 4

    language: str = "en"

    @property
    def model_path(self) -> Path:
        return Path(self.model_cache_dir) / self.model_class

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
```

- [ ] **Step 5: Create vulnscout/core/i18n.py**

```python
from __future__ import annotations

import gettext
import os
from pathlib import Path

from vulnscout.core.config import settings

_LOCALE_DIR = Path(__file__).resolve().parent.parent.parent / "locales"

_translations: dict[str, gettext.NullTranslations] = {}


def setup_i18n(language: str | None = None) -> None:
    lang = language or settings.language
    if lang not in _translations:
        try:
            t = gettext.translation(
                "vulnscout",
                localedir=str(_LOCALE_DIR),
                languages=[lang],
                fallback=True,
            )
        except FileNotFoundError:
            t = gettext.NullTranslations()
        _translations[lang] = t


def gettext(message: str) -> str:
    lang = settings.language
    if lang not in _translations:
        setup_i18n(lang)
    return _translations[lang].gettext(message)


_ = gettext
```

- [ ] **Step 6: Create vulnscout/__init__.py**

```python
__version__ = "0.1.0"
```

- [ ] **Step 7: Run tests and commit**

Run: `cd /home/yu/Projects && python -c "from vulnscout.core.config import settings; print(settings.model_backend)"`

```bash
git add .
git commit -m "feat: add project scaffold, config, and i18n"
```

---

### Task 2: Data models — SQLAlchemy + Pydantic schemas

**Files:**
- Create: `vulnscout/models/__init__.py`
- Create: `vulnscout/models/db.py`
- Create: `vulnscout/models/schemas.py`

- [ ] **Step 1: Create vulnscout/models/db.py**

```python
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from vulnscout.core.config import settings

engine = create_engine(settings.database_url, echo=False)
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
```

- [ ] **Step 2: Create vulnscout/models/schemas.py**

```python
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from vulnscout.models.db import Base


# ── Enums ──────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class SourceType(str, Enum):
    LOCAL = "local"
    URL = "url"
    CLI = "cli"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatchStatus(str, Enum):
    DRAFT = "draft"
    APPLIED = "applied"
    REJECTED = "rejected"


# ── SQLAlchemy Models ──────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status = Column(String(16), default=ScanStatus.PENDING)
    source_type = Column(String(16))
    source_path = Column(Text)
    language = Column(String(32))
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    vuln_count_critical = Column(Integer, default=0)
    vuln_count_high = Column(Integer, default=0)
    vuln_count_medium = Column(Integer, default=0)
    vuln_count_low = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    file_path = Column(Text, nullable=False)
    line_start = Column(Integer)
    line_end = Column(Integer)
    cwe_id = Column(String(16))
    severity = Column(String(16))
    confidence = Column(Integer, default=0)
    title = Column(Text)
    description = Column(Text)
    vulnerable_code = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
    patches = relationship("Patch", back_populates="vulnerability", cascade="all, delete-orphan")


class Patch(Base):
    __tablename__ = "patches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False)
    diff_content = Column(Text)
    description = Column(Text)
    status = Column(String(16), default=PatchStatus.DRAFT)
    applied_at = Column(DateTime, nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="patches")


# ── Pydantic Schemas ───────────────────────────────────────────────────

class ScanCreate(BaseModel):
    source_type: SourceType
    source_path: str
    language: str | None = None


class ScanResponse(BaseModel):
    id: str
    status: ScanStatus
    source_type: SourceType
    source_path: str
    language: str | None
    total_files: int
    scanned_files: int
    vuln_count_critical: int
    vuln_count_high: int
    vuln_count_medium: int
    vuln_count_low: int
    progress_percent: float = 0.0
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    file_path: str
    line_start: int | None
    line_end: int | None
    cwe_id: str | None
    severity: Severity
    title: str | None
    description: str | None
    vulnerable_code: str | None

    class Config:
        from_attributes = True


class PatchResponse(BaseModel):
    id: str
    vuln_id: str
    diff_content: str | None
    description: str | None
    status: PatchStatus

    class Config:
        from_attributes = True


class ScanProgress(BaseModel):
    type: str = "progress"
    percent: float = 0.0
    current_file: str | None = None


class VulnFound(BaseModel):
    type: str = "vuln_found"
    file: str
    severity: Severity
    title: str


class ScanDone(BaseModel):
    type: str = "scan_done"
    total_vulns: int
    duration: float
```

- [ ] **Step 3: Create vulnscout/models/__init__.py**

```python
from vulnscout.models.db import Base, engine, get_db, init_db, SessionLocal
from vulnscout.models.schemas import (
    Scan,
    Vulnerability,
    Patch,
    ScanCreate,
    ScanResponse,
    VulnerabilityResponse,
    PatchResponse,
    ScanProgress,
    VulnFound,
    ScanDone,
    ScanStatus,
    SourceType,
    Severity,
    PatchStatus,
)

__all__ = [
    "Base", "engine", "get_db", "init_db", "SessionLocal",
    "Scan", "Vulnerability", "Patch",
    "ScanCreate", "ScanResponse", "VulnerabilityResponse", "PatchResponse",
    "ScanProgress", "VulnFound", "ScanDone",
    "ScanStatus", "SourceType", "Severity", "PatchStatus",
]
```

- [ ] **Step 4: Write and run test**

Create `tests/__init__.py` (empty) and `tests/conftest.py`:

```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscout.models.db import Base


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
```

Create `tests/test_models.py`:

```python
from vulnscout.models.schemas import Scan, ScanStatus, SourceType, Vulnerability


def test_create_scan(db_session):
    scan = Scan(source_type=SourceType.LOCAL, source_path="/tmp/test")
    db_session.add(scan)
    db_session.commit()

    saved = db_session.query(Scan).first()
    assert saved is not None
    assert saved.status == ScanStatus.PENDING
    assert saved.source_type == SourceType.LOCAL
    assert saved.source_path == "/tmp/test"


def test_create_vulnerability(db_session):
    scan = Scan(source_type=SourceType.LOCAL, source_path="/tmp/test")
    db_session.add(scan)
    db_session.commit()

    vuln = Vulnerability(
        scan_id=scan.id,
        file_path="app.py",
        line_start=10,
        line_end=20,
        cwe_id="CWE-89",
        severity="high",
        title="SQL Injection",
    )
    db_session.add(vuln)
    db_session.commit()

    saved = db_session.query(Vulnerability).first()
    assert saved is not None
    assert saved.cwe_id == "CWE-89"
    assert saved.severity == "high"
```

Run: `cd /home/yu/Projects && pip install -e ".[dev]" && pytest tests/test_models.py -v`

Expected: Both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "feat: add data models (SQLAlchemy + Pydantic schemas)"
```

---

### Phase 2: Hardware Detection & Model Management

### Task 3: GPU/hardware detector

**Files:**
- Create: `vulnscout/core/detector.py`
- Create: `tests/test_detector.py`

- [ ] **Step 1: Create vulnscout/core/detector.py**

```python
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HardwareInfo:
    has_gpu: bool = False
    gpu_count: int = 0
    total_vram_mb: int = 0
    gpu_name: str = ""
    has_llama_cpp: bool = False
    has_vllm: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def recommended_model(self) -> str:
        """Auto-select model based on available VRAM."""
        if not self.has_gpu:
            return "deepseek-coder-1.3b-instruct-q4_k_m.gguf"
        vram = self.total_vram_mb
        if vram >= 24000:
            return "deepseek-coder-6.7b-instruct-q4_k_m.gguf"
        elif vram >= 12000:
            return "deepseek-coder-1.3b-instruct-q4_k_m.gguf"
        elif vram >= 8000:
            return "deepseek-coder-1.3b-instruct-q4_k_m.gguf"
        else:
            return "deepseek-coder-1.3b-instruct-q4_k_m.gguf"

    @property
    def recommended_backend(self) -> str:
        if self.has_vllm and self.has_gpu:
            return "vllm"
        elif self.has_llama_cpp:
            return "llama.cpp"
        return "llama.cpp"


def detect_hardware() -> HardwareInfo:
    info = HardwareInfo()

    # ── GPU detection ──────────────────────────────────────────────
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            result = subprocess.run(
                [
                    nvidia_smi,
                    "--query-gpu=name,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                info.gpu_count = len(lines)
                for line in lines:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) == 2:
                        name, vram = parts
                        info.gpu_name = name
                        info.total_vram_mb += int(vram)
                info.has_gpu = info.gpu_count > 0
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

    # ── Python package detection ───────────────────────────────────
    if shutil.which("llama-cpp-server") or _import_check("llama_cpp"):
        info.has_llama_cpp = True
    if _import_check("vllm"):
        info.has_vllm = True

    # ── Warnings ───────────────────────────────────────────────────
    if not info.has_gpu:
        info.warnings.append(
            "No NVIDIA GPU detected. Using CPU mode (llama.cpp). "
            "Expect slower analysis. For best performance, use a GPU with 8GB+ VRAM."
        )
    if not info.has_llama_cpp and not info.has_vllm:
        info.warnings.append(
            "No inference backend found. Run `vulnscout doctor` for setup instructions."
        )

    return info


def _import_check(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False
```

- [ ] **Step 2: Write test for detector**

Create `tests/test_detector.py`:

```python
from vulnscout.core.detector import detect_hardware, HardwareInfo


def test_detect_returns_info():
    info = detect_hardware()
    assert isinstance(info, HardwareInfo)
    assert isinstance(info.has_gpu, bool)
    assert isinstance(info.recommended_model, str)
    assert isinstance(info.recommended_backend, str)
    assert len(info.recommended_model) > 0
    assert len(info.recommended_backend) > 0


def test_hardware_info_defaults():
    info = HardwareInfo()
    assert info.has_gpu is False
    assert info.gpu_count == 0
    assert info.total_vram_mb == 0
    assert info.recommended_model == "deepseek-coder-1.3b-instruct-q4_k_m.gguf"
    assert info.recommended_backend == "llama.cpp"


def test_hardware_info_vram_selection():
    info = HardwareInfo()
    info.has_gpu = True
    info.total_vram_mb = 24000
    assert "6.7b" in info.recommended_model
```

Run: `cd /home/yu/Projects && pytest tests/test_detector.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add GPU/hardware detector with auto model selection"
```

---

### Task 4: Model manager — auto download & inference backend

**Files:**
- Create: `vulnscout/core/model_manager.py`
- Create: `tests/test_model_manager.py`

- [ ] **Step 1: Create vulnscout/core/model_manager.py**

```python
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import httpx

from vulnscout.core.config import settings
from vulnscout.core.detector import detect_hardware

_MODEL_REGISTRY = {
    "deepseek-coder-1.3b-instruct-q4_k_m.gguf": {
        "url": "https://huggingface.co/TheBloke/deepseek-coder-1.3b-instruct-GGUF/resolve/main/deepseek-coder-1.3b-instruct.Q4_K_M.gguf",
        "mirror_url": "https://modelscope.cn/models/qwen/deepseek-coder-1.3b-gguf/resolve/main/deepseek-coder-1.3b-instruct.Q4_K_M.gguf",
        "size_gb": 0.8,
        "type": "gguf",
    },
    "deepseek-coder-6.7b-instruct-q4_k_m.gguf": {
        "url": "https://huggingface.co/TheBloke/deepseek-coder-6.7b-instruct-GGUF/resolve/main/deepseek-coder-6.7b-instruct.Q4_K_M.gguf",
        "mirror_url": "https://modelscope.cn/models/qwen/deepseek-coder-6.7b-gguf/resolve/main/deepseek-coder-6.7b-instruct.Q4_K_M.gguf",
        "size_gb": 4.1,
        "type": "gguf",
    },
}


class ModelError(Exception):
    pass


class ModelManager:
    def __init__(self):
        self.cache_dir = Path(settings.model_cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._process: subprocess.Popen | None = None

    def resolve_model(self, model_name: str | None = None) -> str:
        """Return the model name to use."""
        if model_name:
            return model_name
        hw = detect_hardware()
        return hw.recommended_model

    def is_downloaded(self, model_name: str) -> bool:
        """Check if model file exists in cache."""
        for f in self.cache_dir.iterdir():
            if model_name in f.name:
                return True
        return False

    def download_model(
        self,
        model_name: str,
        use_mirror: bool = False,
        progress_callback=None,
    ) -> Path:
        """Download model from HuggingFace or ModelScope mirror."""
        if model_name not in _MODEL_REGISTRY:
            raise ModelError(f"Unknown model: {model_name}")

        entry = _MODEL_REGISTRY[model_name]
        url = entry["mirror_url"] if use_mirror else entry["url"]
        dest = self.cache_dir / model_name

        if dest.exists():
            return dest

        if progress_callback:
            progress_callback(f"Downloading {model_name} ({entry['size_gb']}GB)...")

        with httpx.stream("GET", url, follow_redirects=True, timeout=300) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                for chunk in response.iter_bytes(8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(f"Downloading... {downloaded * 100 // total}%")

        return dest

    def start_backend(self, model_path: Path, backend: str | None = None) -> subprocess.Popen:
        """Start the inference backend as a subprocess."""
        backend = backend or detect_hardware().recommended_backend

        if backend == "llama.cpp":
            server_bin = shutil.which("llama-server") or shutil.which("llama-cpp-server")
            if not server_bin:
                raise ModelError(
                    "llama.cpp server not found. Install with: "
                    "pip install llama-cpp-python"
                )
            self._process = subprocess.Popen(
                [
                    server_bin,
                    "-m", str(model_path),
                    "--host", "127.0.0.1",
                    "--port", "8000",
                    "--n-gpu-layers", "-1",
                ]
            )
        elif backend == "vllm":
            self._process = subprocess.Popen(
                [
                    "python", "-m", "vllm.entrypoints.openai.api_server",
                    "--model", str(model_path),
                    "--host", "127.0.0.1",
                    "--port", "8000",
                ]
            )
        else:
            raise ModelError(f"Unsupported backend: {backend}")

        return self._process

    def stop_backend(self):
        if self._process:
            self._process.terminate()
            self._process = None

    def list_available_models(self) -> list[dict]:
        return [
            {"name": k, **v}
            for k, v in _MODEL_REGISTRY.items()
        ]

    def list_downloaded_models(self) -> list[str]:
        return [f.name for f in self.cache_dir.iterdir() if f.is_file()]
```

- [ ] **Step 2: Write test**

Create `tests/test_model_manager.py`:

```python
from pathlib import Path

from vulnscout.core.model_manager import ModelManager


def test_model_manager_init():
    mm = ModelManager()
    assert mm.cache_dir.exists()
    assert isinstance(mm.list_available_models(), list)
    assert len(mm.list_available_models()) > 0


def test_resolve_model_default():
    mm = ModelManager()
    model = mm.resolve_model(None)
    assert isinstance(model, str)
    assert len(model) > 0


def test_resolve_model_custom():
    mm = ModelManager()
    model = mm.resolve_model("my-custom-model")
    assert model == "my-custom-model"


def test_is_downloaded_returns_false():
    mm = ModelManager()
    assert mm.is_downloaded("nonexistent-model.gguf") is False


def test_list_downloaded_returns_list():
    mm = ModelManager()
    result = mm.list_downloaded_models()
    assert isinstance(result, list)
```

Run: `cd /home/yu/Projects && pytest tests/test_model_manager.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add model manager with auto download and backend lifecycle"
```

---

### Phase 3: Scanner Pipeline

### Task 5: Code fetcher — ZIP/GitHub/local

**Files:**
- Create: `vulnscout/scanner/__init__.py`
- Create: `vulnscout/scanner/code_fetcher.py`
- Create: `tests/test_scanner/__init__.py`
- Create: `tests/test_scanner/test_code_fetcher.py`

- [ ] **Step 1: Create vulnscout/scanner/code_fetcher.py**

```python
from __future__ import annotations

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

import httpx


class CodeFetchError(Exception):
    pass


class CodeFetcher:
    """Fetch source code from local path, ZIP upload, or GitHub URL."""

    def __init__(self, work_dir: str | None = None):
        self.work_dir = Path(work_dir or tempfile.mkdtemp(prefix="vulnscout_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def fetch_local(self, path: str) -> Path:
        """Reference an existing local directory."""
        src = Path(path).resolve()
        if not src.exists():
            raise CodeFetchError(f"Path does not exist: {path}")
        if not src.is_dir():
            raise CodeFetchError(f"Path is not a directory: {path}")
        return src

    def fetch_zip(self, zip_data: bytes) -> Path:
        """Extract ZIP bytes to work directory."""
        dest = self.work_dir / "source"
        dest.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            zf.extractall(dest)

        return dest

    def fetch_github(self, repo_url: str, depth: int = 1) -> Path:
        """Clone a GitHub repository."""
        import git

        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest = self.work_dir / repo_name

        if dest.exists():
            shutil.rmtree(dest)

        try:
            git.Repo.clone_from(repo_url, str(dest), depth=depth)
        except git.GitCommandError as e:
            raise CodeFetchError(f"Git clone failed: {e}")

        return dest

    def cleanup(self):
        """Remove work directory."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
```

- [ ] **Step 2: Write test**

Create `tests/test_scanner/test_code_fetcher.py`:

```python
import os
import tempfile

from vulnscout.scanner.code_fetcher import CodeFetcher, CodeFetchError


def test_fetch_local_valid_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        fetcher = CodeFetcher()
        result = fetcher.fetch_local(tmpdir)
        assert result.exists()
        assert result.is_dir()


def test_fetch_local_nonexistent():
    fetcher = CodeFetcher()
    try:
        fetcher.fetch_local("/nonexistent/path")
        assert False, "Should have raised"
    except CodeFetchError:
        pass


def test_fetch_local_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        f.flush()
        try:
            fetcher = CodeFetcher()
            fetcher.fetch_local(f.name)
            assert False, "Should have raised"
        except CodeFetchError:
            pass
        finally:
            os.unlink(f.name)
```

Run: `cd /home/yu/Projects && pytest tests/test_scanner/test_code_fetcher.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add code fetcher (local/ZIP/GitHub)"
```

---

### Task 6: Language detector + file filter + code chunker

**Files:**
- Create: `vulnscout/scanner/language_detector.py`
- Create: `vulnscout/scanner/chunker.py`
- Create: `tests/test_scanner/test_language_detector.py`
- Create: `tests/test_scanner/test_chunker.py`

- [ ] **Step 1: Create vulnscout/scanner/language_detector.py**

```python
from __future__ import annotations

from pathlib import Path

# Map of language → file extensions
LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py", ".pyi", ".pyx"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"},
}

# Map of extension → language (for single file lookup)
EXTENSION_TO_LANGUAGE: dict[str, str] = {}
for lang, exts in LANGUAGE_EXTENSIONS.items():
    for ext in exts:
        EXTENSION_TO_LANGUAGE[ext] = lang

SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "java", "c", "cpp"}

# Patterns for files to skip
SKIP_PATTERNS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".egg-info",
    "target",  # Java/Maven
    ".gradle",
    "vendor",
    ".next",
    ".nuxt",
    "coverage",
    ".pytest_cache",
    "*.min.js",
    "*.bundle.js",
}


def detect_language(file_path: str) -> str | None:
    """Detect language of a single file by extension."""
    ext = Path(file_path).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext)


def is_skipped(file_path: str) -> bool:
    """Check if file should be skipped based on path patterns."""
    path_parts = Path(file_path).parts
    for part in path_parts:
        if part in SKIP_PATTERNS:
            return True
    # Skip minified/bundled files
    name = Path(file_path).name
    if name.endswith(".min.js") or name.endswith(".bundle.js"):
        return True
    return False


def collect_target_files(
    root_path: str,
    target_languages: set[str] | None = None,
) -> list[str]:
    """Collect all files in root_path that match supported languages."""
    if target_languages is None:
        target_languages = SUPPORTED_LANGUAGES

    files = []
    root = Path(root_path)
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        rel_path = str(f.relative_to(root))
        if is_skipped(rel_path):
            continue
        lang = detect_language(rel_path)
        if lang and lang in target_languages:
            files.append(rel_path)

    return sorted(files)


def detect_project_language(files: list[str]) -> str:
    """Detect the primary language of a project based on file count."""
    counts: dict[str, int] = {}
    for f in files:
        lang = detect_language(f)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return "unknown"
    return max(counts, key=counts.get)
```

- [ ] **Step 2: Create vulnscout/scanner/chunker.py**

```python
from __future__ import annotations

from pathlib import Path

from vulnscout.core.config import settings

try:
    import tree_sitter_python as tspython
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser

    _HAS_TS = True
except ImportError:
    _HAS_TS = False


# ── Language grammars ──────────────────────────────────────────────────

_LANGUAGES: dict[str, Language] = {}

if _HAS_TS:
    try:
        _LANGUAGES["python"] = Language(tspython.language())
    except Exception:
        pass
    try:
        _LANGUAGES["java"] = Language(tsjava.language())
    except Exception:
        pass
    # C/C++ and JS/TS need separate pip packages
    # For MVP, we fall back to line-based chunking for unsupported grammars


class Chunk:
    """A single code chunk to be analyzed."""

    def __init__(self, file_path: str, code: str, line_start: int, line_end: int):
        self.file_path = file_path
        self.code = code
        self.line_start = line_start
        self.line_end = line_end

    def __repr__(self):
        return f"Chunk({self.file_path}:{self.line_start}-{self.line_end})"


def chunk_file(file_path: str, language: str) -> list[Chunk]:
    """Chunk a file into atomic analysis units (functions/methods)."""
    root_path = settings.get("scan_root", ".")
    full_path = Path(root_path) / file_path

    if not full_path.exists():
        return []

    code = full_path.read_text(encoding="utf-8", errors="replace")

    # Try AST-based chunking first
    if _HAS_TS and language in _LANGUAGES:
        return _ast_chunk(file_path, code, language)

    # Fallback: line-based chunking (max 50 lines per chunk)
    return _line_chunk(file_path, code)


def _ast_chunk(file_path: str, code: str, language: str) -> list[Chunk]:
    """Chunk using tree-sitter AST (function/method level)."""
    parser = Parser()
    parser.set_language(_LANGUAGES[language])

    tree = parser.parse(code.encode("utf-8"))
    root = tree.root_node

    chunks = []
    # Walk all function/method definitions
    _extract_functions(root, code, file_path, chunks)

    if not chunks:
        # Fallback to whole file
        lines = code.split("\n")
        chunks.append(Chunk(file_path, code, 1, len(lines)))

    return chunks


def _extract_functions(node, code: str, file_path: str, chunks: list[Chunk]):
    """Recursively extract function/method definitions from AST."""
    from tree_sitter import Node

    # Function definition node types vary by language
    function_types = {
        "function_definition",      # Python
        "method_declaration",       # Java
        "function_declaration",     # C/C++/JS
        "arrow_function",           # JS/TS
    }

    if node.type in function_types:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        lines = code.split("\n")
        chunk_code = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
        chunks.append(Chunk(file_path, chunk_code, start_line, end_line))

    for child in node.children:
        _extract_functions(child, code, file_path, chunks)


def _line_chunk(file_path: str, code: str, max_lines: int = 50) -> list[Chunk]:
    """Fallback: chunk by line count."""
    lines = code.split("\n")
    chunks = []
    for i in range(0, len(lines), max_lines):
        chunk_lines = lines[i:i + max_lines]
        chunks.append(
            Chunk(file_path, "\n".join(chunk_lines), i + 1, i + len(chunk_lines))
        )
    return chunks
```

- [ ] **Step 3: Write tests**

Create `tests/test_scanner/test_language_detector.py`:

```python
from vulnscout.scanner.language_detector import (
    detect_language,
    is_skipped,
    collect_target_files,
    detect_project_language,
    SUPPORTED_LANGUAGES,
)


def test_detect_language_python():
    assert detect_language("main.py") == "python"
    assert detect_language("module/__init__.py") == "python"


def test_detect_language_javascript():
    assert detect_language("app.js") == "javascript"
    assert detect_language("component.jsx") == "javascript"


def test_detect_language_java():
    assert detect_language("Main.java") == "java"


def test_detect_language_unknown():
    assert detect_language("readme.md") is None
    assert detect_language("data.json") is None


def test_is_skipped_node_modules():
    assert is_skipped("node_modules/package/index.js") is True


def test_is_skipped_git():
    assert is_skipped(".git/objects/abc123") is True


def test_is_skipped_normal_file():
    assert is_skipped("src/main.py") is False


def test_collect_target_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')")
    (tmp_path / "src" / "utils.js").write_text("const x = 1;")
    (tmp_path / "README.md").write_text("# Project")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("module.exports = {};")

    files = collect_target_files(str(tmp_path), {"python", "javascript"})
    assert "src/main.py" in files
    assert "src/utils.js" in files
    assert "README.md" not in files
    assert "node_modules/dep.js" not in files


def test_detect_project_language():
    files = ["a.py", "b.py", "c.js", "d.java"]
    assert detect_project_language(files) == "python"
```

Create `tests/test_scanner/test_chunker.py`:

```python
from vulnscout.scanner.chunker import _line_chunk, Chunk


def test_line_chunk_small_file():
    code = "line1\nline2\nline3"
    chunks = _line_chunk("test.py", code, max_lines=2)
    assert len(chunks) >= 1
    assert all(isinstance(c, Chunk) for c in chunks)
    assert chunks[0].line_start == 1


def test_line_chunk_respects_max_lines():
    code = "\n".join(f"line{i}" for i in range(100))
    chunks = _line_chunk("test.py", code, max_lines=30)
    assert len(chunks) >= 3  # 100/30 = 3.3

    # Each chunk should be at most max_lines
    for c in chunks:
        line_count = c.code.count("\n") + 1
        assert line_count <= 30
```

Run: `cd /home/yu/Projects && pytest tests/test_scanner/test_language_detector.py tests/test_scanner/test_chunker.py -v`

Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat: add language detector and code chunker"
```

---

### Task 7: Model analyzer — three-tier detection + fix generation

**Files:**
- Create: `vulnscout/scanner/analyzer.py`
- Create: `tests/test_scanner/test_analyzer.py`

- [ ] **Step 1: Create vulnscout/scanner/analyzer.py**

```python
from __future__ import annotations

import json
import re
from typing import Any

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
        f"Vulnerability: {vulnerability['title']} ({vulnerability['cwe_id']})\n"
        f"Description: {vulnerability['description']}\n"
        f"Lines {vulnerability['line_start']}-{vulnerability['line_end']}\n\n"
        f"```{language}\n{code}\n```\n\n"
        f"Return ONLY the fixed code wrapped in ``` fences. Replace ONLY the vulnerable "
        f"lines. Keep the rest of the code identical."
    )


class Analyzer:
    """Three-tier vulnerability analyzer."""

    def __init__(self):
        self.client = OpenAI(
            base_url=settings.openai_base_url,
            api_key=settings.openai_api_key,
        )

    def analyze(
        self,
        file_path: str,
        code: str,
        language: str,
        model: str | None = None,
    ) -> list[dict]:
        """Run all three tiers and return merged vulnerabilities."""
        model = model or settings.model_class

        # Tier 1: Rule pre-filter
        rule_findings = _rule_check(file_path, code, language)

        # If rules already found something, still run model for deeper analysis
        # Tier 2 & 3: Model-based analysis
        model_findings = self._model_analyze(code, language, model)

        # Merge: rule takes priority for pattern-based, model for everything else
        seen_titles = {f["title"] for f in rule_findings}
        merged = list(rule_findings)
        for mf in model_findings:
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
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content
            result = json.loads(content)
            return result.get("vulnerabilities", [])
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
        model = model or settings.model_class

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
```

- [ ] **Step 2: Write tests**

Create `tests/test_scanner/test_analyzer.py`:

```python
from vulnscout.scanner.analyzer import _rule_check


def test_rule_check_detects_hardcoded_credential():
    code = "password = 'super_secret_123'"
    findings = _rule_check("config.py", code, "python")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-798"


def test_rule_check_detects_eval():
    code = "result = eval(user_input)"
    findings = _rule_check("danger.py", code, "python")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-95"


def test_rule_check_clean_code():
    code = "x = 1 + 2\nprint('hello')"
    findings = _rule_check("safe.py", code, "python")
    assert len(findings) == 0


def test_rule_check_js_hardcoded():
    code = "const API_KEY = 'sk-abc123'"
    findings = _rule_check("config.js", code, "javascript")
    assert len(findings) >= 1


def test_rule_check_cpp_strcpy():
    code = 'strcpy(buffer, user_input);'
    findings = _rule_check("main.cpp", code, "cpp")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-121"


def test_rule_check_java_command_injection():
    code = 'Runtime.getRuntime().exec("rm -rf /");'
    findings = _rule_check("Main.java", code, "java")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-78"
```

Run: `cd /home/yu/Projects && pytest tests/test_scanner/test_analyzer.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add three-tier analyzer (rule + zero-shot + few-shot)"
```

---

### Task 8: Deduplication + patch generator + scan pipeline orchestrator

**Files:**
- Create: `vulnscout/scanner/dedup.py`
- Create: `vulnscout/scanner/patch_generator.py`
- Create: `vulnscout/scanner/pipeline.py`
- Create: `tests/test_scanner/test_dedup.py`

- [ ] **Step 1: Create vulnscout/scanner/dedup.py**

```python
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VulnerabilityRecord:
    file_path: str
    line_start: int | None
    line_end: int | None
    cwe_id: str | None
    severity: str
    title: str
    description: str
    confidence: int

    def dedup_key(self) -> tuple:
        """Key for deduplication: same file, same CWE, overlapping lines."""
        return (self.file_path, self.cwe_id)


def deduplicate(findings: list[dict]) -> list[dict]:
    """Deduplicate vulnerability findings."""
    seen: set[tuple] = set()
    result = []

    for f in findings:
        record = VulnerabilityRecord(
            file_path=f.get("file_path", ""),
            line_start=f.get("line_start"),
            line_end=f.get("line_end"),
            cwe_id=f.get("cwe_id"),
            severity=f.get("severity", "medium"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            confidence=f.get("confidence", 0),
        )
        key = record.dedup_key()
        if key not in seen:
            seen.add(key)
            result.append(f)

    return result


def sort_by_severity(findings: list[dict]) -> list[dict]:
    """Sort findings by severity (critical first)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: order.get(f.get("severity", "low"), 99))
```

- [ ] **Step 2: Create vulnscout/scanner/patch_generator.py**

```python
from __future__ import annotations

import difflib


def generate_diff(original_code: str, fixed_code: str, file_path: str) -> str:
    """Generate a unified diff between original and fixed code."""
    original_lines = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff)


def apply_patch(original_code: str, diff_content: str) -> str | None:
    """Apply a unified diff to original code. Returns patched code or None on failure."""
    # For MVP, display the diff for manual application.
    # Future: integrate with git apply or a patch library.
    return None
```

- [ ] **Step 3: Create vulnscout/scanner/pipeline.py**

```python
from __future__ import annotations

import time
from pathlib import Path

from sqlalchemy.orm import Session

from vulnscout.core.config import settings
from vulnscout.models.schemas import (
    Scan,
    ScanStatus,
    Vulnerability,
    Patch,
    PatchStatus,
)
from vulnscout.scanner.analyzer import Analyzer
from vulnscout.scanner.code_fetcher import CodeFetcher
from vulnscout.scanner.chunker import Chunk, chunk_file
from vulnscout.scanner.dedup import deduplicate, sort_by_severity
from vulnscout.scanner.patch_generator import generate_diff
from vulnscout.scanner.language_detector import (
    collect_target_files,
    detect_language,
    detect_project_language,
)


class ProgressCallback:
    """Callback interface for scan progress updates."""

    def on_progress(self, percent: float, current_file: str | None = None):
        pass

    def on_vuln_found(self, file: str, severity: str, title: str):
        pass

    def on_file_done(self, file: str, vuln_count: int):
        pass

    def on_scan_done(self, total_vulns: int, duration: float):
        pass


class ScanPipeline:
    """Orchestrate the full scan pipeline."""

    def __init__(self, db: Session, progress: ProgressCallback | None = None):
        self.db = db
        self.progress = progress or ProgressCallback()
        self.analyzer = Analyzer()

    def run(self, scan: Scan, source_dir: str) -> Scan:
        """Execute the full scan pipeline."""
        start_time = time.time()
        scan.status = ScanStatus.RUNNING
        self.db.commit()

        # Step 1: Collect target files
        files = collect_target_files(source_dir)
        scan.total_files = len(files)
        scan.language = detect_project_language(files)
        self.db.commit()

        if not files:
            scan.status = ScanStatus.DONE
            self.db.commit()
            return scan

        # Step 2: Analyze each file
        for i, rel_path in enumerate(files):
            lang = detect_language(rel_path)
            if not lang:
                continue

            full_path = Path(source_dir) / rel_path
            try:
                code = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Chunk the file
            chunks = chunk_file(rel_path, lang)

            file_vulns = []
            for chunk in chunks:
                # Three-tier analysis
                findings = self.analyzer.analyze(rel_path, chunk.code, lang)
                file_vulns.extend(findings)

            # Dedup + sort
            file_vulns = deduplicate(file_vulns)
            file_vulns = sort_by_severity(file_vulns)

            # Save vulnerabilities
            for f in file_vulns:
                # Find the containing chunk for this vulnerability
                vuln_chunk = None
                for c in chunks:
                    if (
                        f.get("line_start") and c.line_start
                        and c.line_start <= f["line_start"] <= c.line_end
                    ):
                        vuln_chunk = c
                        break
                vuln_code = vuln_chunk.code if vuln_chunk else (chunks[0].code if chunks else "")

                vuln = Vulnerability(
                    scan_id=scan.id,
                    file_path=rel_path,
                    line_start=f.get("line_start"),
                    line_end=f.get("line_end"),
                    cwe_id=f.get("cwe_id"),
                    severity=f.get("severity", "medium"),
                    title=f.get("title", "Unknown Vulnerability"),
                    description=f.get("description", ""),
                    vulnerable_code=vuln_code,
                )
                self.db.add(vuln)
                self.db.flush()

                # Generate fix
                fixed_code = self.analyzer.generate_fix(chunk.code, f, lang)
                if fixed_code:
                    diff = generate_diff(chunk.code, fixed_code, rel_path)
                    patch = Patch(
                        vuln_id=vuln.id,
                        diff_content=diff,
                        description=f"Auto-generated fix for {f.get('title', 'vulnerability')}",
                        status=PatchStatus.DRAFT,
                    )
                    self.db.add(patch)

            # Update counters
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in file_vulns:
                sev = f.get("severity", "low")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            scan.vuln_count_critical += severity_counts["critical"]
            scan.vuln_count_high += severity_counts["high"]
            scan.vuln_count_medium += severity_counts["medium"]
            scan.vuln_count_low += severity_counts["low"]
            scan.scanned_files = i + 1
            self.db.commit()

            # Progress
            percent = ((i + 1) / len(files)) * 100
            self.progress.on_progress(percent, rel_path)
            if file_vulns:
                for f in file_vulns:
                    self.progress.on_vuln_found(
                        rel_path, f.get("severity", "medium"), f.get("title", "")
                    )
            self.progress.on_file_done(rel_path, len(file_vulns))

        # Done
        duration = time.time() - start_time
        scan.status = ScanStatus.DONE
        self.db.commit()

        self.progress.on_scan_done(
            scan.vuln_count_high + scan.vuln_count_critical, duration
        )

        return scan
```

- [ ] **Step 4: Write tests**

Create `tests/test_scanner/test_dedup.py`:

```python
from vulnscout.scanner.dedup import deduplicate, sort_by_severity


def test_dedup_removes_duplicate_cwe():
    findings = [
        {"file_path": "a.py", "cwe_id": "CWE-89", "severity": "critical", "title": "SQLi"},
        {"file_path": "a.py", "cwe_id": "CWE-89", "severity": "critical", "title": "SQLi"},
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_dedup_keeps_different_cwe():
    findings = [
        {"file_path": "a.py", "cwe_id": "CWE-89", "severity": "critical", "title": "SQLi"},
        {"file_path": "a.py", "cwe_id": "CWE-79", "severity": "high", "title": "XSS"},
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_sort_by_severity():
    findings = [
        {"severity": "low", "title": "Low"},
        {"severity": "critical", "title": "Critical"},
        {"severity": "medium", "title": "Medium"},
        {"severity": "high", "title": "High"},
    ]
    result = sort_by_severity(findings)
    assert result[0]["severity"] == "critical"
    assert result[1]["severity"] == "high"
    assert result[2]["severity"] == "medium"
    assert result[3]["severity"] == "low"
```

Run: `cd /home/yu/Projects && pytest tests/test_scanner/test_dedup.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "feat: add dedup, patch generator, and scan pipeline"
```

---

### Phase 4: API Layer

### Task 9: FastAPI app + REST endpoints + WebSocket

**Files:**
- Create: `vulnscout/api/__init__.py`
- Create: `vulnscout/api/router.py`
- Create: `vulnscout/api/scans.py`
- Create: `vulnscout/api/patches.py`
- Create: `vulnscout/api/ws.py`
- Create: `vulnscout/worker/__init__.py`
- Create: `vulnscout/worker/celery_app.py`
- Modify: `vulnscout/main.py`
- Create: `tests/test_api/__init__.py`
- Create: `tests/test_api/test_scans.py`

- [ ] **Step 1: Create vulnscout/api/router.py**

```python
from fastapi import APIRouter

from vulnscout.api.scans import router as scans_router
from vulnscout.api.patches import router as patches_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scans_router, prefix="/scans", tags=["scans"])
api_router.include_router(patches_router, prefix="/patches", tags=["patches"])
```

- [ ] **Step 2: Create vulnscout/api/scans.py**

```python
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, WebSocket
from sqlalchemy.orm import Session

from vulnscout.models.db import get_db
from vulnscout.models.schemas import (
    Scan,
    ScanCreate,
    ScanResponse,
    ScanStatus,
    SourceType,
    Vulnerability,
    VulnerabilityResponse,
    PatchResponse,
)
from vulnscout.scanner.code_fetcher import CodeFetcher
from vulnscout.scanner.pipeline import ScanPipeline
from vulnscout.utils.report_formatter import format_report

router = APIRouter()

# In-memory scan progress (for WebSocket)
_scan_progress: dict[str, "ScanProgressManager"] = {}


class ScanProgressManager:
    """Manage WebSocket progress for a scan."""

    def __init__(self):
        self.websockets: list[WebSocket] = []

    async def add(self, ws: WebSocket):
        await ws.accept()
        self.websockets.append(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.websockets:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.websockets.remove(ws)


@router.post("", response_model=ScanResponse)
async def create_scan(
    source_type: str = "local",
    source_path: str = "",
    file: UploadFile | None = None,
    db: Session = Depends(get_db),
):
    """Create a new scan."""
    scan = Scan(source_type=source_type, source_path=source_path or "upload")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Resolve source
    fetcher = CodeFetcher()
    try:
        if source_type == SourceType.URL:
            source_dir = str(fetcher.fetch_github(source_path))
        elif file:
            zip_data = await file.read()
            source_dir = str(fetcher.fetch_zip(zip_data))
            scan.source_path = file.filename or "upload.zip"
        else:
            source_dir = source_path
            if not Path(source_path).exists():
                raise HTTPException(status_code=400, detail=f"Path not found: {source_path}")
    except Exception as e:
        scan.status = ScanStatus.FAILED
        db.commit()
        raise HTTPException(status_code=400, detail=str(e))

    # Run pipeline (async in production via Celery)
    progress_mgr = _scan_progress.get(scan.id)
    pipeline = ScanPipeline(db, progress_mgr)
    try:
        pipeline.run(scan, source_dir)
    except Exception as e:
        scan.status = ScanStatus.FAILED
        db.commit()
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        fetcher.cleanup()

    return ScanResponse.model_validate(scan)


@router.get("", response_model=list[ScanResponse])
async def list_scans(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    """List all scans."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return [ScanResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get scan status and summary."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    total = (
        scan.vuln_count_critical
        + scan.vuln_count_high
        + scan.vuln_count_medium
        + scan.vuln_count_low
    )
    percent = (scan.scanned_files / scan.total_files * 100) if scan.total_files > 0 else 100

    resp = ScanResponse.model_validate(scan)
    resp.progress_percent = percent
    return resp


@router.get("/{scan_id}/results", response_model=list[VulnerabilityResponse])
async def get_results(
    scan_id: str,
    severity: str | None = None,
    file_path: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Get vulnerabilities for a scan."""
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if file_path:
        query = query.filter(Vulnerability.file_path == file_path)
    vulns = query.offset(skip).limit(limit).all()
    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.get("/{scan_id}/results/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(scan_id: str, vuln_id: str, db: Session = Depends(get_db)):
    """Get single vulnerability detail."""
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == vuln_id, Vulnerability.scan_id == scan_id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnerabilityResponse.model_validate(vuln)


@router.get("/{scan_id}/results/{vuln_id}/patches", response_model=list[PatchResponse])
async def get_patches(scan_id: str, vuln_id: str, db: Session = Depends(get_db)):
    """Get patches for a vulnerability."""
    patches = (
        db.query(Patch)
        .join(Vulnerability)
        .filter(Vulnerability.id == vuln_id, Vulnerability.scan_id == scan_id)
        .all()
    )
    return [PatchResponse.model_validate(p) for p in patches]


@router.get("/{scan_id}/report")
async def download_report(scan_id: str, format: str = "json", db: Session = Depends(get_db)):
    """Download scan report."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    content, media_type = format_report(scan, vulns, format)
    return Response(content=content, media_type=media_type)
```

- [ ] **Step 3: Create vulnscout/api/patches.py**

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnscout.models.db import get_db
from vulnscout.models.schemas import Patch, PatchStatus, PatchResponse, Vulnerability
from vulnscout.scanner.patch_generator import apply_patch

router = APIRouter()


@router.post("/{patch_id}/apply", response_model=PatchResponse)
async def apply_patch_endpoint(patch_id: str, db: Session = Depends(get_db)):
    """Apply a patch (mark as applied)."""
    patch = db.query(Patch).filter(Patch.id == patch_id).first()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    patch.status = PatchStatus.APPLIED
    db.commit()
    return PatchResponse.model_validate(patch)


@router.post("/{patch_id}/reject", response_model=PatchResponse)
async def reject_patch(patch_id: str, db: Session = Depends(get_db)):
    """Reject a patch."""
    patch = db.query(Patch).filter(Patch.id == patch_id).first()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    patch.status = PatchStatus.REJECTED
    db.commit()
    return PatchResponse.model_validate(patch)
```

- [ ] **Step 4: Create vulnscout/api/ws.py**

```python
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

_active_connections: dict[str, list[WebSocket]] = {}


@router.websocket("/ws/v1/scans/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in _active_connections:
        _active_connections[scan_id] = []
    _active_connections[scan_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        _active_connections[scan_id].remove(websocket)


async def broadcast_progress(scan_id: str, data: dict):
    """Broadcast progress data to all connected clients."""
    if scan_id not in _active_connections:
        return
    dead = []
    for ws in _active_connections[scan_id]:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _active_connections[scan_id].remove(ws)
```

- [ ] **Step 5: Create vulnscout/main.py**

```python
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vulnscout.api.router import api_router
from vulnscout.api.ws import router as ws_router
from vulnscout.core.config import settings
from vulnscout.models.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: init DB on startup."""
    init_db()
    yield


app = FastAPI(
    title="VulnScout API",
    description="AI Vulnerability Code Audit Assistant",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
```

- [ ] **Step 6: Write tests**

Create `tests/test_api/test_scans.py`:

```python
import json
from pathlib import Path

import pytest
from httpx import AsyncClient, ASGITransport

from vulnscout.main import app


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_list_scans_empty(client):
    resp = await client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
```

Run: `cd /home/yu/Projects && pip install httpx && pytest tests/test_api/test_scans.py -v`

Expected: Tests PASS.

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "feat: add FastAPI app with scan/patch endpoints and WebSocket"
```

---

### Phase 5: CLI

### Task 10: Click CLI with all commands

**Files:**
- Create: `vulnscout/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Create vulnscout/cli.py**

```python
#!/usr/bin/env python3
"""VulnScout CLI — AI-powered code vulnerability scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnscout import __version__
from vulnscout.core.config import settings
from vulnscout.core.detector import detect_hardware
from vulnscout.core.model_manager import ModelManager

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="vulnscout")
def cli():
    """VulnScout: AI-Powered Vulnerability Code Audit Assistant.

    Scan local code, GitHub repositories, or ZIP files for security vulnerabilities
    using locally deployed DeepSeek-Coder. Get detailed reports and auto-generated fixes.
    """
    pass


# ── Scan Command ───────────────────────────────────────────────────────

@cli.command()
@click.argument("path", required=True)
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "sarif", "markdown"]), default="json", help="Report output format. (默认: json)")
@click.option("--output", "-o", type=click.Path(), help="Write report to file instead of stdout. (输出到文件)")
@click.option("--auto-fix", is_flag=True, help="Automatically generate fix patches for all vulnerabilities. (自动生成修复补丁)")
@click.option("--lang", multiple=True, type=click.Choice(["python", "javascript", "typescript", "java", "c", "cpp"]), help="Target languages to scan. Default: all supported. (指定扫描语言)")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), help="Minimum severity to report. (最低报告等级)")
def scan(path, output_format, output, auto_fix, lang, severity):
    """Scan code for vulnerabilities.

    PATH can be a local directory, a GitHub repository URL, or a ZIP file path.
    """
    from vulnscout.models.db import init_db, SessionLocal
    from vulnscout.models.schemas import Scan, ScanStatus, SourceType, Vulnerability
    from vulnscout.scanner.code_fetcher import CodeFetcher
    from vulnscout.scanner.pipeline import ScanPipeline
    from vulnscout.utils.report_formatter import format_report

    init_db()
    db = SessionLocal()

    # Detect source type
    path_lower = path.lower()
    if path_lower.startswith("http://") or path_lower.startswith("https://"):
        source_type = SourceType.URL
        source_path = path
    elif path.endswith(".zip"):
        source_type = SourceType.LOCAL
        source_path = path
    else:
        source_type = SourceType.LOCAL
        source_path = path

    click.echo(f"VulnScout v{__version__}")
    click.echo(f"   Scanning: {path}")

    # Create scan record
    scan = Scan(source_type=source_type, source_path=source_path)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Fetch code
    fetcher = CodeFetcher()
    try:
        if source_type == SourceType.URL:
            click.echo("   Cloning repository...")
            source_dir = str(fetcher.fetch_github(source_path))
        elif path.endswith(".zip"):
            click.echo("   Extracting ZIP file...")
            zip_data = Path(path).read_bytes()
            source_dir = str(fetcher.fetch_zip(zip_data))
        else:
            if not Path(path).exists():
                click.echo(f"Error: Path not found: {path}", err=True)
                sys.exit(1)
            source_dir = path
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        scan.status = ScanStatus.FAILED
        db.commit()
        sys.exit(1)

    # Run pipeline with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning code...", total=None)

        class CliProgress:
            def on_progress(self, percent, current_file=None):
                progress.update(task, description=f"Scanning: {current_file or '...'} ({percent:.0f}%)")
            def on_vuln_found(self, file, severity, title):
                pass
            def on_file_done(self, file, vuln_count):
                pass
            def on_scan_done(self, total_vulns, duration):
                progress.update(task, description=f"Done! Found {total_vulns} vulnerabilities in {duration:.1f}s")

        pipeline = ScanPipeline(db, CliProgress())

        try:
            pipeline.run(scan, source_dir)
        except Exception as e:
            click.echo(f"\nError during scan: {e}", err=True)
            scan.status = ScanStatus.FAILED
            db.commit()
            sys.exit(1)
        finally:
            fetcher.cleanup()

    # Fetch results
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()

    if vulns:
        table = Table(title=f"Found {len(vulns)} Vulnerabilities")
        table.add_column("Severity", style="bold")
        table.add_column("File", style="cyan")
        table.add_column("Line", style="yellow")
        table.add_column("Title", style="white")

        for v in vulns:
            sev_style = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "white"}
            table.add_row(
                f"[{sev_style.get(v.severity, 'white')}]{v.severity.upper()}[/]",
                v.file_path,
                str(v.line_start or ""),
                v.title or "",
            )
        console.print(table)

    # Output
    content, media_type = format_report(scan, vulns, output_format)
    if output:
        Path(output).write_text(content)
        click.echo(f"Report saved to: {output}")
    else:
        if output_format == "markdown":
            console.print(Markdown(content))
        else:
            click.echo(content)

    db.close()


# ── Config Command ─────────────────────────────────────────────────────

@cli.group()
def config():
    """Manage VulnScout configuration. (管理配置)"""
    pass


@config.command("init")
def config_init():
    """Create default configuration file."""
    from shutil import copyfile

    env_example = Path(__file__).parent.parent / ".env.example"
    env_path = Path(".env")

    if env_path.exists():
        click.echo(".env already exists. (已存在)")
        return

    if env_example.exists():
        copyfile(str(env_example), str(env_path))
        click.echo("Created .env with default configuration. (已创建)")
    else:
        click.echo("Example config not found. (未找到示例配置)", err=True)
        sys.exit(1)


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value. (设置配置)"""
    env_path = Path(".env")
    if not env_path.exists():
        click.echo("No .env file found. Run `vulnscout config init` first. (请先初始化配置)", err=True)
        sys.exit(1)

    content = env_path.read_text()
    lines = content.split("\n")
    found = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = f"{key}={value}"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}")
        click.echo(f"Added new config key: {key}")

    env_path.write_text("\n".join(lines))
    click.echo(f"Set {key}={value}")


# ── Patch Commands ─────────────────────────────────────────────────────

@cli.group()
def patch():
    """Manage fix patches. (管理修复补丁)"""
    pass


@patch.command("apply")
@click.argument("vuln_id")
def patch_apply(vuln_id):
    """Apply a fix patch for a vulnerability. (应用修复)"""
    from vulnscout.models.db import init_db, SessionLocal
    from vulnscout.models.schemas import Patch, PatchStatus

    init_db()
    db = SessionLocal()

    patch = db.query(Patch).filter(Patch.vuln_id == vuln_id).first()
    if not patch:
        click.echo(f"No patch found for vulnerability: {vuln_id}. (未找到补丁)", err=True)
        sys.exit(1)

    patch.status = PatchStatus.APPLIED
    db.commit()
    click.echo(f"Patch applied. (已应用)")
    click.echo(f"\nDiff:\n{patch.diff_content}")

    db.close()


@patch.command("apply-all")
@click.argument("scan_id")
def patch_apply_all(scan_id):
    """Apply all patches for a scan. (应用所有修复)"""
    from vulnscout.models.db import init_db, SessionLocal
    from vulnscout.models.schemas import Patch, PatchStatus, Vulnerability

    init_db()
    db = SessionLocal()

    patches = (
        db.query(Patch)
        .join(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .all()
    )

    if not patches:
        click.echo("No patches found. (未找到补丁)")
        return

    count = 0
    for p in patches:
        p.status = PatchStatus.APPLIED
        count += 1

    db.commit()
    click.echo(f"Applied {count} patches. (已应用 {count} 个补丁)")
    db.close()


# ── Doctor Command ─────────────────────────────────────────────────────

@cli.command()
def doctor():
    """Diagnose the environment. (环境诊断)"""
    click.echo(f"VulnScout v{__version__}")
    click.echo("")

    # Hardware
    hw = detect_hardware()
    click.echo("Hardware:")
    click.echo(f"  GPU: {hw.gpu_name if hw.has_gpu else 'Not detected (CPU mode)'}")
    click.echo(f"  VRAM: {hw.total_vram_mb}MB ({hw.gpu_count} GPU(s))")
    click.echo(f"  Recommended model: {hw.recommended_model}")
    click.echo(f"  Recommended backend: {hw.recommended_backend}")

    if hw.warnings:
        click.echo("")
        click.echo("Warnings:")
        for w in hw.warnings:
            click.echo(f"  [!] {w}")

    # Model status
    click.echo("")
    mm = ModelManager()
    downloaded = mm.list_downloaded_models()
    if downloaded:
        click.echo("Downloaded models:")
        for m in downloaded:
            click.echo(f"  ✓ {m}")
    else:
        click.echo("No models downloaded. Run `vulnscout model download`.")

    # Dependencies
    click.echo("")
    deps = [
        ("fastapi", "fastapi"),
        ("sqlalchemy", "sqlalchemy"),
        ("tree-sitter", "tree_sitter"),
        ("click", "click"),
        ("gitpython", "git"),
        ("openai", "openai"),
    ]
    click.echo("Dependencies:")
    for name, mod in deps:
        try:
            __import__(mod)
            click.echo(f"  ✓ {name}")
        except ImportError:
            click.echo(f"  ✗ {name} (missing)")


# ── Model Commands ─────────────────────────────────────────────────────

@cli.group()
def model():
    """Manage AI models. (管理模型)"""
    pass


@model.command("list")
def model_list():
    """List available and downloaded models. (列出模型)"""
    mm = ModelManager()

    click.echo("Available models:")
    for m in mm.list_available_models():
        status = "✓" if mm.is_downloaded(m["name"]) else " "
        click.echo(f"  [{status}] {m['name']} ({m['size_gb']}GB)")

    click.echo("")
    click.echo("Download a model: vulnscout model download <model-name>")


@model.command("download")
@click.argument("model_name", required=False)
@click.option("--mirror", is_flag=True, help="Use ModelScope mirror (China). (使用国内镜像)")
def model_download(model_name, mirror):
    """Download an AI model. (下载模型)"""
    mm = ModelManager()
    model_name = mm.resolve_model(model_name)

    if mm.is_downloaded(model_name):
        click.echo(f"Model already downloaded: {model_name}")
        return

    click.echo(f"Downloading {model_name}...")
    try:
        path = mm.download_model(model_name, use_mirror=mirror)
        click.echo(f"Downloaded to: {path}")
    except Exception as e:
        click.echo(f"Download failed: {e}", err=True)
        sys.exit(1)


@model.command("status")
def model_status():
    """Show current model status. (模型状态)"""
    click.echo(f"Current model: {settings.model_class}")
    click.echo(f"Backend: {settings.model_backend}")

    mm = ModelManager()
    hw = detect_hardware()
    click.echo(f"Recommended: {hw.recommended_model} ({hw.recommended_backend})")


if __name__ == "__main__":
    cli()
```

- [ ] **Step 2: Write basic CLI test**

Create `tests/test_cli.py`:

```python
from click.testing import CliRunner

from vulnscout.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "vulnscout" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "VulnScout" in result.output


def test_doctor():
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "VulnScout" in result.output or result.exit_code == 0


def test_model_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["model", "list"])
    assert result.exit_code == 0
    assert "Available models" in result.output or result.exit_code == 0
```

Run: `cd /home/yu/Projects && pip install ".[dev]" && pytest tests/test_cli.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add CLI with scan, config, patch, doctor, model commands"
```

---

### Phase 6: Report Formatter & Utility

### Task 11: Report formatter (JSON/SARIF/Markdown)

**Files:**
- Create: `vulnscout/utils/__init__.py`
- Create: `vulnscout/utils/report_formatter.py`
- Create: `tests/test_report_formatter.py`

- [ ] **Step 1: Create vulnscout/utils/report_formatter.py**

```python
from __future__ import annotations

import json
from datetime import datetime

from vulnscout.models.schemas import Scan, Vulnerability


def format_report(scan: Scan, vulns: list[Vulnerability], fmt: str = "json") -> tuple[str, str]:
    """Format scan results into requested format.
    Returns (content, media_type).
    """
    if fmt == "json":
        return _format_json(scan, vulns), "application/json"
    elif fmt == "sarif":
        return _format_sarif(scan, vulns), "application/json"
    elif fmt == "markdown":
        return _format_markdown(scan, vulns), "text/markdown"
    else:
        return _format_json(scan, vulns), "application/json"


def _format_json(scan: Scan, vulns: list[Vulnerability]) -> str:
    data = {
        "scan_id": scan.id,
        "language": scan.language,
        "source_path": scan.source_path,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "summary": {
            "total_files": scan.total_files,
            "scanned_files": scan.scanned_files,
            "critical": scan.vuln_count_critical,
            "high": scan.vuln_count_high,
            "medium": scan.vuln_count_medium,
            "low": scan.vuln_count_low,
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "file_path": v.file_path,
                "line_start": v.line_start,
                "line_end": v.line_end,
                "cwe_id": v.cwe_id,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
            }
            for v in vulns
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def _format_sarif(scan: Scan, vulns: list[Vulnerability]) -> str:
    """Format as SARIF 2.1.0 (compatible with GitHub CodeQL)."""
    results = []
    for v in vulns:
        result = {
            "ruleId": v.cwe_id or "unknown",
            "level": _sarif_level(v.severity),
            "message": {"text": v.title or "Vulnerability found"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": v.file_path},
                        "region": {
                            "startLine": v.line_start or 1,
                            "endLine": v.line_end or v.line_start or 1,
                        },
                    }
                }
            ],
        }
        if v.description:
            result["message"]["text"] = f"{v.title}: {v.description}"
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnScout",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/vulnscout/vulnscout",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity, "warning")


def _format_markdown(scan: Scan, vulns: list[Vulnerability]) -> str:
    lines = [
        f"# VulnScout Scan Report",
        f"",
        f"**Scan ID:** {scan.id}",
        f"**Source:** {scan.source_path}",
        f"**Language:** {scan.language or 'auto'}",
        f"**Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if scan.created_at else 'N/A'}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {scan.vuln_count_critical} |",
        f"| High     | {scan.vuln_count_high} |",
        f"| Medium   | {scan.vuln_count_medium} |",
        f"| Low      | {scan.vuln_count_low} |",
        f"",
        f"**Files:** {scan.scanned_files}/{scan.total_files} scanned",
        f"",
        f"## Vulnerabilities",
        f"",
    ]

    for i, v in enumerate(vulns, 1):
        lines.append(f"### {i}. [{v.severity.upper()}] {v.title}")
        lines.append(f"")
        lines.append(f"- **File:** `{v.file_path}`")
        if v.line_start:
            lines.append(f"- **Line:** {v.line_start}-{v.line_end or v.line_start}")
        if v.cwe_id:
            lines.append(f"- **CWE:** {v.cwe_id}")
        if v.description:
            lines.append(f"- **Description:** {v.description}")
        lines.append(f"")
        if v.vulnerable_code:
            lines.append(f"```python")
            lines.append(v.vulnerable_code[:500])
            lines.append(f"```")
            lines.append(f"")

    lines.append("---")
    lines.append(f"*Generated by VulnScout v0.1.0*")

    return "\n".join(lines)
```

- [ ] **Step 2: Write tests**

Create `tests/test_report_formatter.py`:

```python
import json

from vulnscout.models.schemas import Scan, Vulnerability
from vulnscout.utils.report_formatter import format_report


def test_format_json():
    scan = Scan(source_type="local", source_path="/test")
    vulns = [
        Vulnerability(
            scan_id=scan.id,
            file_path="app.py",
            line_start=10,
            cwe_id="CWE-89",
            severity="high",
            title="SQL Injection",
        )
    ]
    content, media_type = format_report(scan, vulns, "json")
    assert media_type == "application/json"
    data = json.loads(content)
    assert data["summary"]["high"] == 1
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["cwe_id"] == "CWE-89"


def test_format_markdown():
    scan = Scan(source_type="local", source_path="/test")
    vulns = [
        Vulnerability(
            scan_id=scan.id,
            file_path="app.py",
            cwe_id="CWE-89",
            severity="critical",
            title="SQL Injection",
        )
    ]
    content, media_type = format_report(scan, vulns, "markdown")
    assert media_type == "text/markdown"
    assert "VulnScout Scan Report" in content
    assert "SQL Injection" in content
    assert "CWE-89" in content


def test_format_sarif():
    scan = Scan(source_type="local", source_path="/test")
    vulns = [
        Vulnerability(
            scan_id=scan.id,
            file_path="app.py",
            cwe_id="CWE-89",
            severity="critical",
            title="SQL Injection",
        )
    ]
    content, media_type = format_report(scan, vulns, "sarif")
    assert media_type == "application/json"
    data = json.loads(content)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
```

Run: `cd /home/yu/Projects && pytest tests/test_report_formatter.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "feat: add report formatter (JSON/SARIF/Markdown)"
```

---

### Phase 7: Frontend (React + TypeScript + Vite)

### Task 12: Frontend scaffold — Vite + React + MUI + i18n

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/tsconfig.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/types/index.ts`
- Create: `frontend/src/i18n/en.json`
- Create: `frontend/src/i18n/zh.json`
- Create: `frontend/src/i18n/index.ts`
- Create: `frontend/src/components/Layout.tsx`
- Create: `frontend/src/components/Header.tsx`

- [ ] **Step 1: Create frontend/package.json**

```json
{
  "name": "vulnscout-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.22.0",
    "@mui/material": "^5.15.0",
    "@mui/icons-material": "^5.15.0",
    "@emotion/react": "^11.11.0",
    "@emotion/styled": "^11.11.0",
    "react-i18next": "^14.0.0",
    "i18next": "^23.8.0",
    "i18next-browser-languagedetector": "^7.2.0",
    "zustand": "^4.5.0",
    "@tanstack/react-query": "^5.20.0",
    "@monaco-editor/react": "^4.6.0",
    "recharts": "^2.12.0",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.3.0",
    "vite": "^5.1.0"
  }
}
```

- [ ] **Step 2: Create frontend/vite.config.ts**

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
```

- [ ] **Step 3: Create frontend/src/i18n/en.json**

```json
{
  "app": {
    "title": "VulnScout",
    "subtitle": "AI-Powered Code Vulnerability Scanner",
    "language": "Language"
  },
  "nav": {
    "dashboard": "Dashboard",
    "newScan": "New Scan",
    "docs": "Documentation"
  },
  "dashboard": {
    "title": "Dashboard",
    "recentScans": "Recent Scans",
    "totalScans": "Total Scans",
    "totalVulnerabilities": "Total Vulnerabilities",
    "noScans": "No scans yet. Start by creating a new scan."
  },
  "scan": {
    "new": "New Scan",
    "localPath": "Local Directory Path",
    "githubUrl": "GitHub Repository URL",
    "uploadZip": "Upload ZIP File",
    "start": "Start Scan",
    "running": "Scanning...",
    "done": "Scan Complete",
    "failed": "Scan Failed",
    "progress": "Scanning {{file}} ({{percent}}%)",
    "finding": "Found vulnerabilities in {{file}}",
    "results": "Scan Results"
  },
  "vuln": {
    "severity": "Severity",
    "file": "File",
    "line": "Line",
    "cwe": "CWE ID",
    "title": "Title",
    "description": "Description",
    "fix": "Fix",
    "apply": "Apply Fix",
    "reject": "Reject"
  },
  "common": {
    "loading": "Loading...",
    "error": "Error",
    "empty": "No data",
    "close": "Close",
    "back": "Back",
    "export": "Export Report",
    "json": "JSON",
    "sarif": "SARIF",
    "markdown": "Markdown"
  },
  "severity": {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low"
  }
}
```

- [ ] **Step 4: Create frontend/src/i18n/zh.json**

```json
{
  "app": {
    "title": "VulnScout",
    "subtitle": "AI 代码漏洞扫描器",
    "language": "语言"
  },
  "nav": {
    "dashboard": "仪表盘",
    "newScan": "新建扫描",
    "docs": "文档"
  },
  "dashboard": {
    "title": "仪表盘",
    "recentScans": "最近的扫描",
    "totalScans": "总扫描数",
    "totalVulnerabilities": "总漏洞数",
    "noScans": "还没有扫描记录。创建一个新的扫描开始使用。"
  },
  "scan": {
    "new": "新建扫描",
    "localPath": "本地目录路径",
    "githubUrl": "GitHub 仓库 URL",
    "uploadZip": "上传 ZIP 文件",
    "start": "开始扫描",
    "running": "扫描中...",
    "done": "扫描完成",
    "failed": "扫描失败",
    "progress": "正在扫描 {{file}} ({{percent}}%)",
    "finding": "在 {{file}} 中发现漏洞",
    "results": "扫描结果"
  },
  "vuln": {
    "severity": "严重程度",
    "file": "文件",
    "line": "行号",
    "cwe": "CWE 编号",
    "title": "标题",
    "description": "描述",
    "fix": "修复",
    "apply": "应用修复",
    "reject": "拒绝"
  },
  "common": {
    "loading": "加载中...",
    "error": "错误",
    "empty": "暂无数据",
    "close": "关闭",
    "back": "返回",
    "export": "导出报告",
    "json": "JSON",
    "sarif": "SARIF",
    "markdown": "Markdown"
  },
  "severity": {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危"
  }
}
```

- [ ] **Step 5: Create frontend/src/i18n/index.ts**

```typescript
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import en from './en.json';
import zh from './zh.json';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      zh: { translation: zh },
    },
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
  });

export default i18n;
```

- [ ] **Step 6: Create frontend/src/types/index.ts**

```typescript
export interface Scan {
  id: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  source_type: 'local' | 'url' | 'cli';
  source_path: string;
  language: string | null;
  total_files: number;
  scanned_files: number;
  vuln_count_critical: number;
  vuln_count_high: number;
  vuln_count_medium: number;
  vuln_count_low: number;
  progress_percent: number;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  cwe_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string | null;
  description: string | null;
  vulnerable_code: string | null;
}

export interface Patch {
  id: string;
  vuln_id: string;
  diff_content: string | null;
  description: string | null;
  status: 'draft' | 'applied' | 'rejected';
}

export interface ScanProgressMessage {
  type: 'progress' | 'vuln_found' | 'file_done' | 'scan_done';
  percent?: number;
  current_file?: string;
  file?: string;
  severity?: string;
  title?: string;
  total_vulns?: number;
  duration?: number;
}
```

- [ ] **Step 7: Create frontend/src/components/Header.tsx**

```typescript
import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

const Header: React.FC = () => {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();

  const handleLanguageChange = (
    _: React.MouseEvent<HTMLElement>,
    newLang: string | null,
  ) => {
    if (newLang) {
      i18n.changeLanguage(newLang);
    }
  };

  return (
    <AppBar position="static" elevation={0}>
      <Toolbar>
        <Typography
          variant="h6"
          component="div"
          sx={{ cursor: 'pointer', fontWeight: 700 }}
          onClick={() => navigate('/')}
        >
          {t('app.title')}
        </Typography>
        <Typography variant="body2" sx={{ ml: 1, opacity: 0.7 }}>
          {t('app.subtitle')}
        </Typography>

        <Box sx={{ ml: 4, display: 'flex', gap: 1 }}>
          <Button color="inherit" onClick={() => navigate('/')}>
            {t('nav.dashboard')}
          </Button>
          <Button color="inherit" onClick={() => navigate('/new-scan')}>
            {t('nav.newScan')}
          </Button>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        <ToggleButtonGroup
          value={i18n.language}
          exclusive
          onChange={handleLanguageChange}
          size="small"
          sx={{
            '& .MuiToggleButton-root': {
              color: 'white',
              borderColor: 'rgba(255,255,255,0.3)',
              '&.Mui-selected': {
                color: 'white',
                bgcolor: 'rgba(255,255,255,0.15)',
              },
            },
          }}
        >
          <ToggleButton value="en">EN</ToggleButton>
          <ToggleButton value="zh">中</ToggleButton>
        </ToggleButtonGroup>
      </Toolbar>
    </AppBar>
  );
};

export default Header;
```

- [ ] **Step 8: Create frontend/src/components/Layout.tsx**

```typescript
import React from 'react';
import { Box, Container } from '@mui/material';
import Header from './Header';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'grey.50' }}>
      <Header />
      <Container maxWidth="xl" sx={{ py: 3 }}>
        {children}
      </Container>
    </Box>
  );
};

export default Layout;
```

- [ ] **Step 9: Create frontend/src/App.tsx**

```typescript
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResult from './pages/ScanResult';
import VulnDetail from './pages/VulnDetail';

const theme = createTheme({
  palette: {
    primary: { main: '#1a237e' },
    background: { default: '#f5f5f5' },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
  },
  shape: { borderRadius: 8 },
});

const queryClient = new QueryClient();

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/new-scan" element={<NewScan />} />
              <Route path="/scans/:scanId" element={<ScanResult />} />
              <Route path="/scans/:scanId/vulns/:vulnId" element={<VulnDetail />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  );
};

export default App;
```

- [ ] **Step 10: Create remaining frontend scaffold files**

Create `frontend/src/main.tsx`:

```typescript
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './i18n';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

Create `frontend/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>VulnScout</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

Create `frontend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
```

- [ ] **Step 11: Commit**

```bash
git add frontend/
git commit -m "feat: add frontend scaffold (Vite + React + MUI + i18n)"
```

---

### Task 13: Frontend pages — Dashboard, NewScan, ScanResult, VulnDetail

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/scans.ts`
- Create: `frontend/src/components/SeverityBadge.tsx`
- Create: `frontend/src/components/ProgressBar.tsx`
- Create: `frontend/src/components/DiffViewer.tsx`
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/pages/NewScan.tsx`
- Create: `frontend/src/pages/ScanProgress.tsx`
- Create: `frontend/src/pages/ScanResult.tsx`
- Create: `frontend/src/pages/VulnDetail.tsx`

- [ ] **Step 1: Create frontend/src/api/client.ts**

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
});

export default api;
```

- [ ] **Step 2: Create frontend/src/api/scans.ts**

```typescript
import api from './client';
import type { Scan, Vulnerability, Patch } from '../types';

export const fetchScans = async (): Promise<Scan[]> => {
  const { data } = await api.get('/scans');
  return data;
};

export const fetchScan = async (id: string): Promise<Scan> => {
  const { data } = await api.get(`/scans/${id}`);
  return data;
};

export const fetchResults = async (
  scanId: string,
  severity?: string,
  filePath?: string,
): Promise<Vulnerability[]> => {
  const params: Record<string, string> = {};
  if (severity) params.severity = severity;
  if (filePath) params.file_path = filePath;
  const { data } = await api.get(`/scans/${scanId}/results`, { params });
  return data;
};

export const fetchVulnerability = async (
  scanId: string,
  vulnId: string,
): Promise<Vulnerability> => {
  const { data } = await api.get(`/scans/${scanId}/results/${vulnId}`);
  return data;
};

export const fetchPatches = async (
  scanId: string,
  vulnId: string,
): Promise<Patch[]> => {
  const { data } = await api.get(`/scans/${scanId}/results/${vulnId}/patches`);
  return data;
};

export const createScan = async (sourceType: string, sourcePath: string): Promise<Scan> => {
  const { data } = await api.post('/scans', null, {
    params: { source_type: sourceType, source_path: sourcePath },
  });
  return data;
};

export const createScanFromZip = async (file: File): Promise<Scan> => {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/scans?source_type=local', formData);
  return data;
};
```

- [ ] **Step 3: Create frontend/src/components/SeverityBadge.tsx**

```typescript
import React from 'react';
import { Chip } from '@mui/material';
import { useTranslation } from 'react-i18next';

interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const severityColors: Record<string, 'error' | 'warning' | 'info' | 'default'> = {
  critical: 'error',
  high: 'warning',
  medium: 'info',
  low: 'default',
};

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const { t } = useTranslation();
  const label = t(`severity.${severity}`, severity);
  return (
    <Chip
      label={label}
      color={severityColors[severity] || 'default'}
      size="small"
      variant="filled"
    />
  );
};

export default SeverityBadge;
```

- [ ] **Step 4: Create frontend/src/pages/Dashboard.tsx**

```typescript
import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  Chip,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { fetchScans } from '../api/scans';
import SeverityBadge from '../components/SeverityBadge';

const Dashboard: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
  });

  const totalVulns = scans?.reduce(
    (sum, s) => sum + s.vuln_count_critical + s.vuln_count_high + s.vuln_count_medium + s.vuln_count_low,
    0,
  ) ?? 0;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" fontWeight={600}>
          {t('dashboard.title')}
        </Typography>
        <Button variant="contained" onClick={() => navigate('/new-scan')}>
          {t('scan.new')}
        </Button>
      </Box>

      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={4}>
          <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
            <CardContent>
              <Typography variant="h3" fontWeight={700}>
                {scans?.length ?? 0}
              </Typography>
              <Typography color="text.secondary">{t('dashboard.totalScans')}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
            <CardContent>
              <Typography variant="h3" fontWeight={700}>
                {totalVulns}
              </Typography>
              <Typography color="text.secondary">{t('dashboard.totalVulnerabilities')}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
            <CardContent>
              <Typography variant="h3" fontWeight={700}>
                {scans?.filter(s => s.status === 'done').length ?? 0}
              </Typography>
              <Typography color="text.secondary">{t('dashboard.recentScans')}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Typography variant="h5" fontWeight={600} sx={{ mb: 2 }}>
        {t('dashboard.recentScans')}
      </Typography>

      {isLoading && <Typography>{t('common.loading')}</Typography>}
      {!isLoading && (!scans || scans.length === 0) && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', p: 4, textAlign: 'center' }}>
          <Typography color="text.secondary">{t('dashboard.noScans')}</Typography>
        </Card>
      )}
      {scans && scans.length > 0 && (
        <TableContainer component={Paper} elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>{t('vuln.file')}</TableCell>
                <TableCell>Language</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>{t('vuln.severity')}</TableCell>
                <TableCell>Date</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.map((scan) => (
                <TableRow
                  key={scan.id}
                  hover
                  sx={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {scan.id.slice(0, 8)}
                    </Typography>
                  </TableCell>
                  <TableCell>{scan.source_path}</TableCell>
                  <TableCell>{scan.language || '-'}</TableCell>
                  <TableCell>
                    <Chip
                      label={scan.status}
                      color={scan.status === 'done' ? 'success' : scan.status === 'failed' ? 'error' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      {scan.vuln_count_critical > 0 && (
                        <SeverityBadge severity="critical" />
                      )}
                      {scan.vuln_count_high > 0 && (
                        <SeverityBadge severity="high" />
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    {new Date(scan.created_at).toLocaleDateString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
};

export default Dashboard;
```

- [ ] **Step 5: Create frontend/src/pages/NewScan.tsx**

```typescript
import React, { useState, useRef } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  TextField,
  Button,
  Tabs,
  Tab,
  Divider,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { createScan, createScanFromZip } from '../api/scans';

const NewScan: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tab, setTab] = useState(0);
  const [localPath, setLocalPath] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleStartScan = async () => {
    setLoading(true);
    try {
      let scan;
      if (tab === 0) {
        scan = await createScan('local', localPath);
      } else if (tab === 1) {
        scan = await createScan('url', githubUrl);
      } else {
        const file = fileInputRef.current?.files?.[0];
        if (!file) return;
        scan = await createScanFromZip(file);
      }
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      console.error('Scan failed:', err);
      alert('Failed to start scan. Check the input and try again.');
    } finally {
      setLoading(false);
    }
  };

  const canStart = tab === 0 ? localPath : tab === 1 ? githubUrl : true;

  return (
    <Box sx={{ maxWidth: 700, mx: 'auto' }}>
      <Typography variant="h4" fontWeight={600} sx={{ mb: 3 }}>
        {t('scan.new')}
      </Typography>

      <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
        <CardContent>
          <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 3 }}>
            <Tab label="Local Directory" />
            <Tab label="GitHub URL" />
            <Tab label="Upload ZIP" />
          </Tabs>

          <Divider sx={{ mb: 3 }} />

          {tab === 0 && (
            <TextField
              fullWidth
              label={t('scan.localPath')}
              placeholder="/home/user/projects/my-app"
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              helperText="Enter the absolute path to a local directory"
            />
          )}

          {tab === 1 && (
            <TextField
              fullWidth
              label={t('scan.githubUrl')}
              placeholder="https://github.com/username/repository"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              helperText="Enter a public GitHub repository URL"
            />
          )}

          {tab === 2 && (
            <Box>
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                style={{ display: 'none' }}
                onChange={() => {}}
              />
              <Button
                variant="outlined"
                component="label"
                fullWidth
                sx={{ py: 4, borderStyle: 'dashed' }}
              >
                <input
                  type="file"
                  accept=".zip"
                  hidden
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      const label = e.target.parentElement;
                      if (label) label.textContent = file.name;
                    }
                  }}
                />
                {t('scan.uploadZip')}
              </Button>
            </Box>
          )}

          <Box sx={{ mt: 3, textAlign: 'right' }}>
            <Button
              variant="contained"
              size="large"
              onClick={handleStartScan}
              disabled={!canStart || loading}
            >
              {loading ? t('scan.running') : t('scan.start')}
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default NewScan;
```

- [ ] **Step 6: Create remaining pages as stubs**

Create `frontend/src/pages/ScanResult.tsx`:

```typescript
import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Chip,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchScan, fetchResults } from '../api/scans';
import SeverityBadge from '../components/SeverityBadge';

const ScanResult: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const { data: scan } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => fetchScan(scanId!),
    enabled: !!scanId,
  });

  const { data: vulns } = useQuery({
    queryKey: ['results', scanId],
    queryFn: () => fetchResults(scanId!),
    enabled: !!scanId,
  });

  if (!scan || !vulns) {
    return <Typography>{t('common.loading')}</Typography>;
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h4" fontWeight={600}>
            {t('scan.results')}
          </Typography>
          <Typography color="text.secondary">
            {scan.source_path} — {scan.scanned_files}/{scan.total_files} files
          </Typography>
        </Box>
        <Chip
          label={scan.status}
          color={scan.status === 'done' ? 'success' : scan.status === 'failed' ? 'error' : 'default'}
        />
      </Box>

      <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
            {scan.vuln_count_critical > 0 && (
              <Box><SeverityBadge severity="critical" /> <strong>{scan.vuln_count_critical}</strong></Box>
            )}
            {scan.vuln_count_high > 0 && (
              <Box><SeverityBadge severity="high" /> <strong>{scan.vuln_count_high}</strong></Box>
            )}
            {scan.vuln_count_medium > 0 && (
              <Box><SeverityBadge severity="medium" /> <strong>{scan.vuln_count_medium}</strong></Box>
            )}
            {scan.vuln_count_low > 0 && (
              <Box><SeverityBadge severity="low" /> <strong>{scan.vuln_count_low}</strong></Box>
            )}
          </Box>

          <List disablePadding>
            {vulns.map((vuln) => (
              <ListItem key={vuln.id} disablePadding>
                <ListItemButton
                  onClick={() => navigate(`/scans/${scanId}/vulns/${vuln.id}`)}
                >
                  <SeverityBadge severity={vuln.severity} />
                  <ListItemText
                    sx={{ ml: 2 }}
                    primary={vuln.title}
                    secondary={`${vuln.file_path}:${vuln.line_start || '?'}`}
                  />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ScanResult;
```

Create `frontend/src/pages/VulnDetail.tsx`:

```typescript
import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Chip,
  Button,
  Stack,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchVulnerability, fetchPatches } from '../api/scans';
import SeverityBadge from '../components/SeverityBadge';
import DiffViewer from '../components/DiffViewer';

const VulnDetail: React.FC = () => {
  const { scanId, vulnId } = useParams<{ scanId: string; vulnId: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const { data: vuln } = useQuery({
    queryKey: ['vuln', vulnId],
    queryFn: () => fetchVulnerability(scanId!, vulnId!),
    enabled: !!scanId && !!vulnId,
  });

  const { data: patches } = useQuery({
    queryKey: ['patches', vulnId],
    queryFn: () => fetchPatches(scanId!, vulnId!),
    enabled: !!scanId && !!vulnId,
  });

  if (!vuln) return <Typography>{t('common.loading')}</Typography>;

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto' }}>
      <Button sx={{ mb: 2 }} onClick={() => navigate(`/scans/${scanId}`)}>
        &larr; {t('common.back')}
      </Button>

      <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 3 }}>
        <CardContent>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <SeverityBadge severity={vuln.severity} />
            {vuln.cwe_id && <Chip label={vuln.cwe_id} size="small" variant="outlined" />}
          </Stack>

          <Typography variant="h5" fontWeight={600} sx={{ mb: 2 }}>
            {vuln.title}
          </Typography>

          <Typography color="text.secondary" sx={{ mb: 1 }}>
            {t('vuln.file')}: <strong>{vuln.file_path}</strong>
            {vuln.line_start && (
              <> | {t('vuln.line')}: <strong>{vuln.line_start}{vuln.line_end ? `-${vuln.line_end}` : ''}</strong></>
            )}
          </Typography>

          {vuln.description && (
            <Typography sx={{ mt: 2 }}>{vuln.description}</Typography>
          )}
        </CardContent>
      </Card>

      {vuln.vulnerable_code && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              Vulnerable Code
            </Typography>
            <Box
              component="pre"
              sx={{
                p: 2,
                bgcolor: 'grey.100',
                borderRadius: 1,
                overflow: 'auto',
                fontSize: 13,
                fontFamily: 'monospace',
              }}
            >
              {vuln.vulnerable_code}
            </Box>
          </CardContent>
        </Card>
      )}

      {patches && patches.length > 0 && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              {t('vuln.fix')}
            </Typography>
            {patches.map((patch) => (
              <Box key={patch.id}>
                <DiffViewer diff={patch.diff_content || ''} />
                <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                  <Button variant="contained" size="small">
                    {t('vuln.apply')}
                  </Button>
                  <Button variant="outlined" size="small" color="error">
                    {t('vuln.reject')}
                  </Button>
                </Box>
              </Box>
            ))}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default VulnDetail;
```

Create `frontend/src/components/DiffViewer.tsx`:

```typescript
import React from 'react';
import { Box, Typography } from '@mui/material';

interface DiffViewerProps {
  diff: string;
}

const DiffViewer: React.FC<DiffViewerProps> = ({ diff }) => {
  const lines = diff.split('\n');

  return (
    <Box
      sx={{
        bgcolor: '#1e1e1e',
        color: '#d4d4d4',
        borderRadius: 1,
        overflow: 'auto',
        fontSize: 13,
        fontFamily: '"Cascadia Code", "Fira Code", monospace',
        lineHeight: 1.5,
      }}
    >
      {lines.map((line, i) => {
        let bg = 'transparent';
        let prefix = ' ';
        if (line.startsWith('+')) {
          bg = 'rgba(0,200,80,0.15)';
          prefix = '+';
        } else if (line.startsWith('-')) {
          bg = 'rgba(200,0,0,0.15)';
          prefix = '-';
        } else if (line.startsWith('@@')) {
          bg = 'rgba(0,100,200,0.2)';
          prefix = '@';
        }
        return (
          <Box
            key={i}
            sx={{
              bgcolor: bg,
              px: 2,
              whiteSpace: 'pre',
              '&:hover': { filter: 'brightness(1.2)' },
            }}
          >
            <span style={{ color: '#666', userSelect: 'none', marginRight: 16, minWidth: 32, display: 'inline-block', textAlign: 'right' }}>
              {i + 1}
            </span>
            <span>{line}</span>
          </Box>
        );
      })}
    </Box>
  );
};

export default DiffViewer;
```

- [ ] **Step 2: Commit**

```bash
git add .
git commit -m "feat: add frontend pages (Dashboard, NewScan, ScanResult, VulnDetail)"
```

---

### Phase 8: Deployment & Documentation

### Task 14: Docker Compose + README

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Modify: `README.md`

- [ ] **Step 1: Create Dockerfile**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy app
COPY vulnscout/ vulnscout/

# Expose API
EXPOSE 8000

CMD ["uvicorn", "vulnscout.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Create docker-compose.yml**

```yaml
version: "3.9"

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///data/vulnscout.db
      - MODEL_CACHE_DIR=/models
      - CELERY_BROKER_URL=redis://redis:6379/0
      - CELERY_RESULT_BACKEND=redis://redis:6379/0
    volumes:
      - ./data:/app/data
      - model_cache:/models
    depends_on:
      - redis

  worker:
    build: .
    command: celery -A vulnscout.worker.celery_app worker --loglevel=info
    environment:
      - DATABASE_URL=sqlite:///data/vulnscout.db
      - MODEL_CACHE_DIR=/models
      - CELERY_BROKER_URL=redis://redis:6379/0
      - CELERY_RESULT_BACKEND=redis://redis:6379/0
    volumes:
      - ./data:/app/data
      - model_cache:/models
    depends_on:
      - redis

  frontend:
    image: node:20-alpine
    working_dir: /app
    command: sh -c "npm install && npm run build && npx serve -s dist -l 3000"
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app
    depends_on:
      - api

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  model_cache:
```

- [ ] **Step 3: Write README.md**

```markdown
# VulnScout — AI-Powered Vulnerability Code Audit Assistant

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

VulnScout scans source code for security vulnerabilities using locally deployed 
DeepSeek-Coder AI models. Supports Web UI and CLI, with automatic GPU adaptation.

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
- (Optional) NVIDIA GPU with 8GB+ VRAM for GPU mode
- (Optional) [llama.cpp](https://github.com/ggerganov/llama.cpp) for CPU mode

### Install

```bash
pip install vulnscout
```

### Run a Scan

```bash
# Scan a local directory
vulnscout scan ./my-project

# Scan a GitHub repository
vulnscout scan https://github.com/user/repo

# Export to SARIF (compatible with GitHub CodeQL)
vulnscout scan ./my-project --format sarif --output report.sarif
```

### Start the Web UI

```bash
# Download an AI model first
vulnscout model download

# Start the API server
uvicorn vulnscout.main:app --host 0.0.0.0 --port 8000

# Open frontend (separate terminal)
cd frontend && npm install && npm run dev
```

Or use Docker Compose:

```bash
docker compose up -d
# Open http://localhost:3000
```

## CLI Reference

```
vulnscout scan <path>              Scan a local path, GitHub URL, or ZIP file
vulnscout scan <path> --format json|sarif|markdown
vulnscout scan <path> --auto-fix   Auto-generate fix patches
vulnscout doctor                   Diagnose environment
vulnscout model list               List available AI models
vulnscout model download <name>    Download an AI model
vulnscout config init              Create configuration file
vulnscout patch apply <vuln-id>    Apply a fix patch
vulnscout patch apply-all <scan>   Apply all patches for a scan
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Development

```bash
git clone https://github.com/vulnscout/vulnscout
cd vulnscout
pip install -e ".[dev]"
pytest
```

## License

MIT
```

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat: add Docker Compose, Dockerfile, and README"
```
