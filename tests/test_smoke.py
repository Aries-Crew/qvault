"""Bootstrap 煙霧測試——確認套件可 import、CI 綠。真正的測試隨各交付項進來。"""
import qvault_core


def test_package_imports():
    assert qvault_core.__version__ == "0.0.1"
