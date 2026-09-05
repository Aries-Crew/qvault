"""QVault core — post-quantum-ready hybrid envelope encryption."""

from .aead import DEK_LEN, KEY_LEN, TAG_LEN, gen_dek, seal, unseal
from .container import (
    QVaultHeader,
    body_chunk_count,
    deserialize,
    is_last_chunk,
    nonce_for,
)
from .errors import (
    QVaultDecryptError,
    QVaultError,
    QVaultFormatError,
    QVaultVersionError,
)
from .kek import WRAP_AAD, KeyEncapsulation, ScryptKEK

__version__ = "0.0.1"

__all__ = [
    "QVaultError",
    "QVaultFormatError",
    "QVaultVersionError",
    "QVaultDecryptError",
    "QVaultHeader",
    "deserialize",
    "nonce_for",
    "body_chunk_count",
    "is_last_chunk",
    "gen_dek",
    "seal",
    "unseal",
    "KeyEncapsulation",
    "ScryptKEK",
    "WRAP_AAD",
    "KEY_LEN",
    "DEK_LEN",
    "TAG_LEN",
    "__version__",
]
