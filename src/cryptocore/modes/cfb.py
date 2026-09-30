"""Режим AES-128 CFB с размером сегмента 128 бит."""

from cryptocore.aes import BLOCK_SIZE, encrypt_block
from cryptocore.modes._utils import validate_iv, xor_bytes


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрование данных в режиме CFB-128 без дополнения."""
    validate_iv(iv)

    encrypted_fragments = []
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        fragment = data[offset : offset + BLOCK_SIZE]
        keystream = encrypt_block(key, feedback)
        ciphertext_fragment = xor_bytes(fragment, keystream[: len(fragment)])
        encrypted_fragments.append(ciphertext_fragment)
        if len(fragment) == BLOCK_SIZE:
            feedback = ciphertext_fragment
    return b"".join(encrypted_fragments)


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Расшифрование данных в режиме CFB-128 без дополнения."""
    validate_iv(iv)

    decrypted_fragments = []
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        ciphertext_fragment = data[offset : offset + BLOCK_SIZE]
        keystream = encrypt_block(key, feedback)
        plaintext_fragment = xor_bytes(
            ciphertext_fragment, keystream[: len(ciphertext_fragment)]
        )
        decrypted_fragments.append(plaintext_fragment)
        if len(ciphertext_fragment) == BLOCK_SIZE:
            feedback = ciphertext_fragment
    return b"".join(decrypted_fragments)
