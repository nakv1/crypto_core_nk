"""Иерархия ключей из задания m7: HMAC(master, context || INT32_BE(i)).

Название файла рекомендовано заданием. Это счётчиковая схема, а не HKDF
Extract/Expand из RFC 5869. Здесь нет получения ключей из пароля.
"""

from cryptocore.kdf._validation import binary, key_length
from cryptocore.mac import HMAC


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """Детерминированно получает ключ назначения; context кодируется UTF-8."""
    key_length(length)
    master_key = binary(master_key, "master_key")
    if not isinstance(context, str):
        raise TypeError("context must be a string")
    context_bytes = context.encode("utf-8")
    prf = HMAC(master_key)
    result = bytearray()
    for counter in range(1, (length + 31) // 32 + 1):
        block = prf.digest_message(context_bytes + counter.to_bytes(4, "big"))
        result.extend(block[:min(32, length - len(result))])
    return bytes(result)
