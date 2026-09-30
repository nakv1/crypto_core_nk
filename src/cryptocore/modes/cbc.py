"""Режим AES-128 CBC с явной обработкой блоков."""

from cryptocore.aes import BLOCK_SIZE, decrypt_block, encrypt_block
from cryptocore.modes._utils import validate_iv, xor_bytes
from cryptocore.padding import pad, unpad


class CiphertextLengthError(ValueError):
    """Ошибка длины шифротекста CBC."""


def encrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрование полных блоков CBC без дополнения."""
    validate_iv(iv)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("raw CBC input length must be a multiple of 16 bytes")

    encrypted_blocks = []
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        ciphertext_block = encrypt_block(key, xor_bytes(block, feedback))
        encrypted_blocks.append(ciphertext_block)
        feedback = ciphertext_block
    return b"".join(encrypted_blocks)


def decrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Расшифрование полных блоков CBC без удаления дополнения."""
    validate_iv(iv)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("raw CBC input length must be a multiple of 16 bytes")

    decrypted_blocks = []
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[offset : offset + BLOCK_SIZE]
        plaintext_block = xor_bytes(decrypt_block(key, ciphertext_block), feedback)
        decrypted_blocks.append(plaintext_block)
        feedback = ciphertext_block
    return b"".join(decrypted_blocks)


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрование данных CBC с дополнением PKCS#7."""
    return encrypt_raw(key, iv, pad(data))


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Расшифрование данных CBC с проверкой PKCS#7."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise CiphertextLengthError(
            "ciphertext length must be a positive multiple of 16 bytes"
        )

    return unpad(decrypt_raw(key, iv, data))
