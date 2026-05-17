from pathlib import Path

from vulnscout.core.model_manager import ModelManager


def test_model_manager_init():
    mm = ModelManager()
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
