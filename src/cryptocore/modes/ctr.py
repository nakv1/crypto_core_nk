"""Режим AES-128 CTR со 128-битным счётчиком."""

from cryptocore.aes import BLOCK_SIZE, encrypt_block
from cryptocore.modes._utils import validate_iv, xor_bytes


_COUNTER_MODULUS = 1 << (BLOCK_SIZE * 8)


def _transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Преобразование данных общей для CTR операцией."""
    validate_iv(iv)

    output_fragments = []
    counter = int.from_bytes(iv, "big")
    for offset in range(0, len(data), BLOCK_SIZE):
        fragment = data[offset : offset + BLOCK_SIZE]
        counter_block = counter.to_bytes(BLOCK_SIZE, "big")
        keystream = encrypt_block(key, counter_block)
        output_fragments.append(xor_bytes(fragment, keystream[: len(fragment)]))
        counter = (counter + 1) % _COUNTER_MODULUS
    return b"".join(output_fragments)


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрование данных в режиме CTR без дополнения."""
    return _transform(key, iv, data)


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Расшифрование данных в режиме CTR без дополнения."""
    return _transform(key, iv, data)
