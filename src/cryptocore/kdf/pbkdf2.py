"""Собственный PBKDF2-HMAC-SHA256 по RFC 2898 / RFC 8018, раздел 5.2."""

from functools import lru_cache
from importlib import import_module
from importlib.util import find_spec
import os

from cryptocore.kdf._validation import binary, key_length, positive_integer
from cryptocore.mac import HMAC


@lru_cache(maxsize=1)
def _load_chain():
    if find_spec("numba") is None:
        return None
    return import_module("cryptocore.kdf.accelerated_pbkdf2").process


def _get_chain(iterations):
    # На коротких цепочках загрузка NumPy/Numba стоит дороже самого вычисления.
    if (iterations < 1000 or iterations > (1 << 63) - 1
            or os.environ.get("CRYPTOCORE_PURE_PYTHON") == "1"):
        return None
    return _load_chain()


def pbkdf2_hmac_sha256(password, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """Возвращает ровно dklen байт; строки пароля кодируются UTF-8.

    Salt всегда бинарный. В CLI hex разбирается до вызова этой функции.
    Итерации положительны, длина — 1..(2^32-1)*32 байт.
    """
    positive_integer(iterations, "iterations")
    key_length(dklen)
    password = password.encode("utf-8") if isinstance(password, str) else binary(password, "password")
    salt = binary(salt, "salt")
    prf = HMAC(password)
    chain = _get_chain(iterations)
    result = bytearray()
    for counter in range(1, (dklen + 31) // 32 + 1):
        first = prf.digest_message(salt + counter.to_bytes(4, "big"))
        if chain is not None:
            # Начальные состояния взяты из HMAC спринта 5, U1 вычислен им же.
            block = chain(prf._inner_base._state, prf._outer_base._state, first, iterations)
        else:
            previous = first
            accumulated = int.from_bytes(first, "big")
            for _ in range(1, iterations):
                previous = prf.digest_message(previous)
                accumulated ^= int.from_bytes(previous, "big")
            block = accumulated.to_bytes(32, "big")
        result.extend(block[:min(32, dklen - len(result))])
    return bytes(result)
