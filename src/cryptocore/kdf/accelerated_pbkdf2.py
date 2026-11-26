"""Компиляция цепочки собственного HMAC на ядре SHA-256 спринта 5.

Ключевые состояния и U1 приходят из класса HMAC. Здесь выполняются U2..Uc
и XOR. Готовые PBKDF2/HMAC/SHA из библиотек не используются.
"""

import numpy as np
from numba import njit

from cryptocore.hash.accelerated_sha256 import _compress


@njit(cache=True, inline="always")
def _write_words(block, words):
    for index in range(8):
        word = words[index]
        for byte in range(4):
            block[index * 4 + byte] = np.uint8(word >> (24 - 8 * byte))


@njit(cache=True, nogil=True)
def _chain(inner_seed, outer_seed, first, iterations):
    previous = first.copy()
    accumulated = first.copy()
    block = np.zeros(64, dtype=np.uint8)
    block[32] = 0x80
    # ipad/opad (64 байта) + digest (32 байта): 96 * 8 = 768 бит.
    block[62] = 3
    for _ in range(1, iterations):
        _write_words(block, previous)
        inner = inner_seed.copy()
        _compress(inner, block)
        _write_words(block, inner)
        outer = outer_seed.copy()
        _compress(outer, block)
        for index in range(8):
            accumulated[index] ^= outer[index]
        previous = outer
    return accumulated


def process(inner_state, outer_state, first, iterations):
    words = np.array([int.from_bytes(first[i:i + 4], "big") for i in range(0, 32, 4)], dtype=np.uint32)
    result = _chain(np.array(inner_state, dtype=np.uint32),
                    np.array(outer_state, dtype=np.uint32), words, iterations)
    return b"".join(int(word).to_bytes(4, "big") for word in result)
