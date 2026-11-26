"""Общие границы функций с 32-битным номером блока."""

MAX_KEY_BYTES = ((1 << 32) - 1) * 32


def positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def key_length(value):
    positive_integer(value, "length")
    if value > MAX_KEY_BYTES:
        raise ValueError("length exceeds the 32-bit block counter limit")
    return value


def binary(value, name):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)
