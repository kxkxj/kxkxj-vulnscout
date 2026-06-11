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
    has_ollama: bool = False
    has_llama_cpp: bool = False
    has_vllm: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def recommended_model(self) -> str:
        """Auto-select Ollama model tag based on available VRAM."""
        if not self.has_gpu:
            return "deepseek-coder:1.3b"
        vram = self.total_vram_mb
        if vram >= 24000:
            return "deepseek-coder:6.7b"
        elif vram >= 8000:
            return "deepseek-coder:1.3b"
        else:
            return "deepseek-coder:1.3b"

    @property
    def recommended_backend(self) -> str:
        if self.has_ollama:
            return "ollama"
        elif self.has_vllm and self.has_gpu:
            return "vllm"
        elif self.has_llama_cpp:
            return "llama.cpp"
        return "ollama"


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

    # ── Ollama detection ───────────────────────────────────────────
    info.has_ollama = shutil.which("ollama") is not None

    # ── Other backend detection ────────────────────────────────────
    if shutil.which("llama-cpp-server") or _import_check("llama_cpp"):
        info.has_llama_cpp = True
    if _import_check("vllm"):
        info.has_vllm = True

    # ── Warnings ───────────────────────────────────────────────────
    if not info.has_gpu:
        info.warnings.append(
            "No NVIDIA GPU detected. Using CPU mode (Ollama). "
            "Expect slower analysis. For best performance, use a GPU with 8GB+ VRAM."
        )
    if not info.has_ollama:
        info.warnings.append(
            "Ollama not found. Install it first:\n"
            "  curl -fsSL https://ollama.com/install.sh | sh\n"
            "Then pull a model: ollama pull deepseek-coder:1.3b"
        )

    return info


def _import_check(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False
