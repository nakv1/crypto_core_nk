"""Получение ключей из паролей и мастер-ключей."""

from cryptocore.kdf.hkdf import derive_key
from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256

__all__ = ["derive_key", "pbkdf2_hmac_sha256"]
