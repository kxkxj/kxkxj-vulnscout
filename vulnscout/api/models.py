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
    all_models = mm.list_available_models()
    local = [m for m in all_models if m["provider"] == "ollama"]
    cloud = [m for m in all_models if m["provider"] != "ollama"]
    for m in local:
        m["downloaded"] = mm.is_downloaded(m["name"])
    return {"current": {"provider": settings.model_provider.value, "model": settings.model_name, "api_url": settings.openai_base_url if settings.is_cloud else settings.ollama_api_url}, "local": local, "cloud": cloud, "recommended": hw.recommended_model}

class SwitchModelRequest(BaseModel):
    model_name: str

@router.post("/models/switch")
async def switch_model(req: SwitchModelRequest):
    env_path = Path(".env")
    if not env_path.exists():
        raise HTTPException(400, "No .env file found")
    model_name = req.model_name
    known_ollama = {"deepseek-coder:1.3b", "deepseek-coder:6.7b", "codellama", "llama3", "mistral", "qwen2"}
    known_openai = {"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"}
    provider = "ollama" if model_name in known_ollama else ("openai" if model_name in known_openai else "custom")
    content = env_path.read_text()
    lines = content.split("\n")
    updated, set_name, set_prov = [], False, False
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
    return {"status": "ok", "model": model_name, "provider": provider}
