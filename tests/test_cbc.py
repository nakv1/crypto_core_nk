import pytest

from cryptocore.modes._utils import xor_bytes
from cryptocore.modes.cbc import (
    CiphertextLengthError,
    decrypt,
    decrypt_raw,
    encrypt,
    encrypt_raw,
)
from cryptocore.padding import PaddingError


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CIPHERTEXT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)


def test_encrypt_raw_matches_full_nist_sp_800_38a_f_2_1_vector():
    assert encrypt_raw(KEY, IV, PLAINTEXT) == CIPHERTEXT


def test_decrypt_raw_matches_full_nist_sp_800_38a_f_2_1_vector():
    assert decrypt_raw(KEY, IV, CIPHERTEXT) == PLAINTEXT


@pytest.mark.parametrize(
    "data",
    [
        PLAINTEXT,
        bytes(range(256)),
        b"\x00\xff" * 32,
    ],
)
def test_raw_functions_round_trip_without_changing_length(data):
    ciphertext = encrypt_raw(KEY, IV, data)
    decrypted = decrypt_raw(KEY, IV, ciphertext)

    assert len(ciphertext) == len(data)
    assert len(decrypted) == len(ciphertext)
    assert decrypted == data


def test_raw_functions_accept_empty_data():
    assert encrypt_raw(KEY, IV, b"") == b""
    assert decrypt_raw(KEY, IV, b"") == b""


@pytest.mark.parametrize("operation", [encrypt_raw, decrypt_raw])
def test_raw_functions_require_complete_blocks(operation):
    with pytest.raises(ValueError, match="multiple of 16 bytes"):
        operation(KEY, IV, b"incomplete")


@pytest.mark.parametrize("invalid_iv", [b"x" * 15, b"x" * 17])
@pytest.mark.parametrize(
    ("operation", "data"),
    [
        (encrypt_raw, b""),
        (decrypt_raw, b""),
        (encrypt, b""),
        (decrypt, b"x" * 16),
    ],
)
def test_cbc_functions_reject_wrong_iv_length(operation, data, invalid_iv):
    with pytest.raises(ValueError, match="IV must be exactly 16 bytes"):
        operation(KEY, invalid_iv, data)


def test_xor_bytes_rejects_different_lengths():
    with pytest.raises(ValueError, match="equal length"):
        xor_bytes(b"short", b"longer")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"short text",
        b"exactly-16-bytes",
        bytes(range(64)),
        b"A" * 37,
        bytes([0x00, 0xFF, 0x10, 0x80]) * 23,
    ],
)
def test_encrypt_then_decrypt_returns_original_bytes(data):
    assert decrypt(KEY, IV, encrypt(KEY, IV, data)) == data


@pytest.mark.parametrize("ciphertext", [b"", b"x" * 15, b"x" * 17])
def test_decrypt_rejects_invalid_ciphertext_length(ciphertext):
    with pytest.raises(CiphertextLengthError):
        decrypt(KEY, IV, ciphertext)


def test_decrypt_rejects_invalid_padding():
    invalid_padded_block = b"A" * 15 + b"\x00"
    ciphertext = encrypt_raw(KEY, IV, invalid_padded_block)

    with pytest.raises(PaddingError):
        decrypt(KEY, IV, ciphertext)
