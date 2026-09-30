"""Общие небольшие вспомогательные функции режимов шифрования."""

from cryptocore.aes import BLOCK_SIZE


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Выполнение XOR двух байтовых строк одинаковой длины."""
    if len(left) != len(right):
        raise ValueError("byte sequences must have equal length")

    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def validate_iv(iv: bytes) -> None:
    """Проверка длины вектора инициализации AES."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes")
