"""Операции AES-128 над одним блоком через PyCryptodome."""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def encrypt_block(key: bytes, block: bytes) -> bytes:
    """Шифрование одного 16-байтного блока AES-128."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes")

    return AES.new(key, AES.MODE_ECB).encrypt(block)


def decrypt_block(key: bytes, block: bytes) -> bytes:
    """Расшифрование одного 16-байтного блока AES-128."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes")

    return AES.new(key, AES.MODE_ECB).decrypt(block)
