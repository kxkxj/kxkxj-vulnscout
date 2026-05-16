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
