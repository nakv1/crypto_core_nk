import pytest

from cryptocore.aes import encrypt_block
from cryptocore.modes._utils import xor_bytes
from cryptocore.modes.ctr import decrypt, encrypt


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CIPHERTEXT = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)


def test_encrypt_matches_full_nist_sp_800_38a_f_5_1_vector():
    assert encrypt(KEY, IV, PLAINTEXT) == CIPHERTEXT


def test_decrypt_matches_full_nist_sp_800_38a_f_5_1_vector():
    assert decrypt(KEY, IV, CIPHERTEXT) == PLAINTEXT


@pytest.mark.parametrize("length", [1, 15, 17, 33, 50])
def test_partial_data_matches_nist_vector_prefix(length):
    plaintext = PLAINTEXT[:length]
    ciphertext = CIPHERTEXT[:length]

    assert encrypt(KEY, IV, plaintext) == ciphertext
    assert decrypt(KEY, IV, ciphertext) == plaintext


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 33])
def test_round_trip_preserves_length_at_block_boundaries(length):
    data = bytes(range(length))

    ciphertext = encrypt(KEY, IV, data)
    plaintext = decrypt(KEY, IV, ciphertext)

    assert len(ciphertext) == len(data)
    assert len(plaintext) == len(ciphertext)
    assert plaintext == data


@pytest.mark.parametrize(
    "data",
    [
        b"short text",
        b"exactly-16-bytes",
        bytes(range(64)),
        b"A" * 37,
        bytes([0x00, 0xFF, 0x10, 0x80]) * 23,
    ],
)
def test_encrypt_then_decrypt_returns_original_bytes(data):
    assert decrypt(KEY, IV, encrypt(KEY, IV, data)) == data


def test_ctr_functions_apply_the_same_transformation():
    data = bytes([0x00, 0xFF, 0x10, 0x80]) * 17

    assert encrypt(KEY, IV, data) == decrypt(KEY, IV, data)


def test_ctr_functions_accept_empty_data():
    assert encrypt(KEY, IV, b"") == b""
    assert decrypt(KEY, IV, b"") == b""


@pytest.mark.parametrize("operation", [encrypt, decrypt])
@pytest.mark.parametrize("invalid_iv", [b"x" * 15, b"x" * 17])
def test_ctr_functions_reject_wrong_iv_length(operation, invalid_iv):
    with pytest.raises(ValueError, match="IV must be exactly 16 bytes"):
        operation(KEY, invalid_iv, b"")


def test_counter_wraps_from_maximum_value_to_zero():
    iv = b"\xff" * 16
    data = bytes(range(32))
    first_keystream = encrypt_block(KEY, b"\xff" * 16)
    second_keystream = encrypt_block(KEY, b"\x00" * 16)
    expected = xor_bytes(data[:16], first_keystream) + xor_bytes(
        data[16:], second_keystream
    )

    assert encrypt(KEY, iv, data) == expected
