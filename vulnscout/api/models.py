from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from vulnscout.core.config import settings
from vulnscout.core.detector import detect_hardware
from vulnscout.core.model_manager import ModelManager

router = APIRouter()


@router.get("/models")
async def list_models():
    mm = ModelManager()
    hw = detect_hardware()

    # Dynamically detect what's actually available
    available = mm.get_actually_available_models()

    return {
        "current": {
            "provider": settings.model_provider.value,
            "model": settings.model_name,
            "api_url": settings.openai_base_url if settings.is_cloud else settings.ollama_api_url,
        },
        "local": available["local"],
        "cloud": available["cloud"],
        "downloadable": available["downloadable"],
        "recommended": hw.recommended_model,
        "ollama_running": available["ollama_running"],
        "ollama_installed": available["ollama_installed"],
        "cloud_configured": available["cloud_configured"],
    }


class SwitchModelRequest(BaseModel):
    model_name: str


@router.post("/models/switch")
async def switch_model(req: SwitchModelRequest):
    env_path = Path(".env")
    if not env_path.exists():
        raise HTTPException(400, "No .env file found. Run `vulnscout config init` first.")

    model_name = req.model_name

    # Dynamically determine provider based on what's available
    mm = ModelManager()
    available = mm.get_actually_available_models()

    # Check if it's a local Ollama model (either downloaded or downloadable)
    is_ollama_model = any(
        m["name"] == model_name for m in available["local"] + available["downloadable"]
    )
    # Check if it's a known cloud model
    is_cloud_model = any(m["name"] == model_name for m in available["cloud"])

    if is_ollama_model:
        provider = "ollama"
    elif is_cloud_model:
        provider = "openai"
    else:
        # Unknown model — check if it looks like an Ollama tag or something else
        if ":" in model_name or "/" in model_name:
            provider = "ollama"
        else:
            provider = "custom"

    # Write to .env file
    content = env_path.read_text()
    lines = content.split("\n")
    updated = []
    set_name = False
    set_prov = False

    for line in lines:
        if line.startswith("MODEL_NAME="):
            updated.append(f"MODEL_NAME={model_name}")
            set_name = True
        elif line.startswith("MODEL_PROVIDER="):
            updated.append(f"MODEL_PROVIDER={provider}")
            set_prov = True
        else:
            updated.append(line)

    if not set_name:
        updated.append(f"MODEL_NAME={model_name}")
    if not set_prov:
        updated.append(f"MODEL_PROVIDER={provider}")

    env_path.write_text("\n".join(updated))

    # Hot-reload the runtime settings so they take effect immediately
    settings.reload()

    return {
        "status": "ok",
        "model": model_name,
        "provider": provider,
        "effective": {
            "model": settings.model_name,
            "provider": settings.model_provider.value,
        },
    }
