import pytest

from cryptocore.modes.ecb import (
    CiphertextLengthError,
    decrypt,
    decrypt_raw,
    encrypt,
    encrypt_raw,
)


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
PLAINTEXT_BLOCK = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
CIPHERTEXT_BLOCK = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")


def test_encrypt_raw_matches_nist_sp_800_38a_f_1_1():
    assert encrypt_raw(KEY, PLAINTEXT_BLOCK) == CIPHERTEXT_BLOCK


def test_decrypt_raw_matches_nist_sp_800_38a_f_1_1():
    assert decrypt_raw(KEY, CIPHERTEXT_BLOCK) == PLAINTEXT_BLOCK


def test_raw_functions_do_not_change_length_or_apply_padding():
    plaintext = PLAINTEXT_BLOCK * 2

    ciphertext = encrypt_raw(KEY, plaintext)

    assert len(ciphertext) == len(plaintext)
    assert len(decrypt_raw(KEY, ciphertext)) == len(ciphertext)
    assert decrypt_raw(KEY, ciphertext) == plaintext


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"short text",
        b"exactly-16-bytes",
        bytes(range(64)),
        b"\x00\xff\x00\xff" * 17,
    ],
)
def test_encrypt_then_decrypt_returns_original_bytes(plaintext):
    assert decrypt(KEY, encrypt(KEY, plaintext)) == plaintext


@pytest.mark.parametrize("ciphertext", [b"", b"x" * 15])
def test_decrypt_rejects_invalid_ciphertext_length(ciphertext):
    with pytest.raises(CiphertextLengthError):
        decrypt(KEY, ciphertext)


@pytest.mark.parametrize("operation", [encrypt_raw, decrypt_raw])
def test_raw_functions_require_complete_blocks(operation):
    with pytest.raises(ValueError):
        operation(KEY, b"incomplete")
