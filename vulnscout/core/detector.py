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
