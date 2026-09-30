"""Режим AES-128 OFB с явным построением гаммы."""

from cryptocore.aes import BLOCK_SIZE, encrypt_block
from cryptocore.modes._utils import validate_iv, xor_bytes


def _transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Преобразование данных общей для OFB операцией."""
    validate_iv(iv)

    output_fragments = []
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        fragment = data[offset : offset + BLOCK_SIZE]
        feedback = encrypt_block(key, feedback)
        output_fragments.append(xor_bytes(fragment, feedback[: len(fragment)]))
    return b"".join(output_fragments)


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрование данных в режиме OFB без дополнения."""
    return _transform(key, iv, data)


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Расшифрование данных в режиме OFB без дополнения."""
    return _transform(key, iv, data)
