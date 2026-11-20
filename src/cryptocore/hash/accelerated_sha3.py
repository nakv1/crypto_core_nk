"""Собственная Keccak-f[1600] на uint64, компилируемая Numba."""

import numpy as np
from numba import njit

from cryptocore.hash.sha3_256 import _ROUND_CONSTANTS, _ROTATION_OFFSETS

_CONSTANTS = np.array(_ROUND_CONSTANTS, dtype=np.uint64)
_ROTATIONS = np.array(_ROTATION_OFFSETS, dtype=np.uint64)


@njit(cache=True, inline="always")
def _rol(value, shift):
    if shift == 0:
        return value
    return (value << shift) | (value >> (np.uint64(64) - shift))


@njit(cache=True, nogil=True)
def _absorb(state, data):
    columns = np.empty(5, dtype=np.uint64)
    differences = np.empty(5, dtype=np.uint64)
    rotated = np.empty(25, dtype=np.uint64)
    for start in range(0, len(data), 136):
        for i in range(17):
            lane = np.uint64(0)
            for j in range(8):
                lane |= np.uint64(data[start + i * 8 + j]) << np.uint64(j * 8)
            state[i] ^= lane
        for constant in _CONSTANTS:
            # theta
            for x in range(5):
                columns[x] = (state[x] ^ state[x + 5] ^ state[x + 10]
                              ^ state[x + 15] ^ state[x + 20])
            for x in range(5):
                differences[x] = columns[(x - 1) % 5] ^ _rol(
                    columns[(x + 1) % 5], np.uint64(1))
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] ^= differences[x]
            # rho, pi
            for y in range(5):
                for x in range(5):
                    source = x + 5 * y
                    target = y + 5 * ((2 * x + 3 * y) % 5)
                    rotated[target] = _rol(state[source], _ROTATIONS[source])
            # chi, iota
            for y in range(5):
                row = 5 * y
                for x in range(5):
                    state[row + x] = (rotated[row + x]
                        ^ ((~rotated[row + (x + 1) % 5]) & rotated[row + (x + 2) % 5]))
            state[0] ^= constant


def process(state, data):
    """Поглощает полные блоки без копирования входного буфера."""
    lanes = np.array(state, dtype=np.uint64)
    _absorb(lanes, np.frombuffer(data, dtype=np.uint8))
    return lanes.tolist()
