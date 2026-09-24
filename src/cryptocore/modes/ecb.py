"""Режим AES-128 ECB с явной обработкой блоков."""

from cryptocore.aes import BLOCK_SIZE, decrypt_block, encrypt_block
from cryptocore.padding import pad, unpad


class CiphertextLengthError(ValueError):
    """Ошибка длины шифротекста ECB."""


def encrypt_raw(key: bytes, data: bytes) -> bytes:
    """Шифрование полных блоков без дополнения."""
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("raw ECB input length must be a multiple of 16 bytes")

    encrypted_blocks = []
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        encrypted_blocks.append(encrypt_block(key, block))
    return b"".join(encrypted_blocks)


def decrypt_raw(key: bytes, data: bytes) -> bytes:
    """Расшифрование полных блоков без удаления дополнения."""
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("raw ECB input length must be a multiple of 16 bytes")

    decrypted_blocks = []
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        decrypted_blocks.append(decrypt_block(key, block))
    return b"".join(decrypted_blocks)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Шифрование данных с дополнением PKCS#7."""
    return encrypt_raw(key, pad(plaintext))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Расшифрование данных с проверкой PKCS#7."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise CiphertextLengthError(
            "ciphertext length must be a positive multiple of 16 bytes"
        )

    return unpad(decrypt_raw(key, ciphertext))
