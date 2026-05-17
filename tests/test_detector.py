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
    assert info.recommended_model == "deepseek-coder:1.3b"
    assert info.recommended_backend == "ollama"


def test_hardware_info_vram_selection():
    info = HardwareInfo()
    info.has_gpu = True
    info.total_vram_mb = 24000
    assert "6.7b" in info.recommended_model
