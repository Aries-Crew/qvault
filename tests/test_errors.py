"""錯誤體系(ADR-001「錯誤體系」/ AC #1 第二條)。"""

import pytest

from qvault_core.errors import (
    QVaultDecryptError,
    QVaultError,
    QVaultFormatError,
    QVaultVersionError,
)

_SIBLINGS = (QVaultFormatError, QVaultVersionError, QVaultDecryptError)


@pytest.mark.parametrize("exc", _SIBLINGS)
def test_all_errors_derive_from_base(exc):
    assert issubclass(exc, QVaultError)
    assert issubclass(QVaultError, Exception)


def test_siblings_are_disjoint():
    """三者是兄弟而非巢狀——呼叫端要能分開 catch(格式壞 / 版本未知 / 解密失敗)。"""
    for a in _SIBLINGS:
        for b in _SIBLINGS:
            if a is not b:
                assert not issubclass(a, b)


def test_base_catches_all():
    for exc in _SIBLINGS:
        with pytest.raises(QVaultError):
            raise exc("boom")
