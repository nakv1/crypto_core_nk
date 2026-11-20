"""Собственные раунды SHA-256 на целых uint32, компилируемые Numba."""

import numpy as np
from numba import njit

from cryptocore.hash.sha256 import _ROUND_CONSTANTS

_CONSTANTS = np.array(_ROUND_CONSTANTS, dtype=np.uint32)


@njit(cache=True, inline="always")
def _ror(value, shift):
    return np.uint32((value >> shift) | (value << (32 - shift)))


@njit(cache=True, nogil=True)
def _compress(state, data):
    words = np.empty(64, dtype=np.uint32)
    for start in range(0, len(data), 64):
        for i in range(16):
            j = start + 4 * i
            words[i] = (np.uint32(data[j]) << 24
                        | np.uint32(data[j + 1]) << 16
                        | np.uint32(data[j + 2]) << 8
                        | np.uint32(data[j + 3]))
        for i in range(16, 64):
            x, y = words[i - 15], words[i - 2]
            s0 = _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)
            s1 = _ror(y, 17) ^ _ror(y, 19) ^ (y >> 10)
            words[i] = np.uint32(words[i - 16] + s0 + words[i - 7] + s1)

        a, b, c, d, e, f, g, h = state
        for i in range(64):
            s1 = _ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)
            choice = g ^ (e & (f ^ g))
            t1 = np.uint32(h + s1 + choice + _CONSTANTS[i] + words[i])
            s0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
            majority = (a & b) | (c & (a | b))
            h, g, f, e, d, c, b, a = (
                g, f, e, np.uint32(d + t1), c, b, a,
                np.uint32(t1 + s0 + majority),
            )
        values = (a, b, c, d, e, f, g, h)
        for i in range(8):
            state[i] = np.uint32(state[i] + values[i])


def process(state, data):
    """Обрабатывает полные блоки без копирования входного буфера."""
    words = np.array(state, dtype=np.uint32)
    _compress(words, np.frombuffer(data, dtype=np.uint8))
    return words.tolist()
