import hashlib
import re

import pytest

from cryptocore.hash import SHA256


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039"
            "a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"a" * 1_000_000,
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0",
        ),
    ],
    ids=["empty", "abc", "long_message", "million_a"],
)
def test_sha256_known_answers(message, expected):
    sha256 = SHA256()
    sha256.update(message)

    assert sha256.hexdigest() == expected


@pytest.mark.parametrize("length", [0, 1, 55, 56, 63, 64, 65, 119, 120, 128])
def test_sha256_padding_boundaries(length):
    message = bytes((index * 37 + 11) % 256 for index in range(length))
    sha256 = SHA256()
    sha256.update(message)

    assert sha256.digest() == hashlib.sha256(message).digest()


@pytest.mark.parametrize("length", [2, 17, 31, 257, 1000, 4097])
def test_sha256_deterministic_messages(length):
    message = bytes((index * 19 + length) % 256 for index in range(length))
    sha256 = SHA256()
    sha256.update(message)

    assert sha256.hexdigest() == hashlib.sha256(message).hexdigest()


@pytest.mark.parametrize("chunk_size", [1, 7, 64, 100])
def test_sha256_chunk_sizes_match_single_update(chunk_size):
    message = bytes((index * 29 + 5) % 256 for index in range(2049))
    expected = SHA256()
    expected.update(message)

    chunked = SHA256()
    for offset in range(0, len(message), chunk_size):
        chunked.update(message[offset : offset + chunk_size])

    assert chunked.digest() == expected.digest()
    assert chunked.digest() == hashlib.sha256(message).digest()


@pytest.mark.parametrize(
    "value",
    [
        b"bytes-like input",
        bytearray(b"bytes-like input"),
        memoryview(b"bytes-like input"),
    ],
)
def test_sha256_accepts_supported_bytes_like_types(value):
    sha256 = SHA256()
    sha256.update(value)

    assert sha256.digest() == hashlib.sha256(b"bytes-like input").digest()


@pytest.mark.parametrize("value", ["abc", 123, None, [1, 2, 3]])
def test_sha256_rejects_unsupported_types(value):
    with pytest.raises(TypeError, match="data must be bytes-like"):
        SHA256().update(value)


def test_sha256_empty_update_does_not_change_digest():
    sha256 = SHA256()
    sha256.update(b"abc")
    before = sha256.digest()

    assert sha256.update(b"") is None
    assert sha256.digest() == before


def test_sha256_update_returns_none():
    assert SHA256().update(b"abc") is None


def test_sha256_digest_and_hexdigest_are_repeatable_in_any_order():
    sha256 = SHA256()
    sha256.update(b"abc")
    expected_digest = hashlib.sha256(b"abc").digest()
    expected_hexdigest = hashlib.sha256(b"abc").hexdigest()

    assert sha256.digest() == expected_digest
    assert sha256.digest() == expected_digest
    assert sha256.hexdigest() == expected_hexdigest
    assert sha256.hexdigest() == expected_hexdigest
    assert sha256.digest() == expected_digest

    reverse_order = SHA256()
    reverse_order.update(b"abc")
    assert reverse_order.hexdigest() == expected_hexdigest
    assert reverse_order.digest() == expected_digest


def test_sha256_update_continues_after_digest_and_hexdigest():
    sha256 = SHA256()
    sha256.update(b"abc")
    assert sha256.digest() == hashlib.sha256(b"abc").digest()
    assert sha256.hexdigest() == hashlib.sha256(b"abc").hexdigest()

    sha256.update(b"def")

    assert sha256.digest() == hashlib.sha256(b"abcdef").digest()


def test_sha256_result_sizes_and_hex_format():
    sha256 = SHA256()
    sha256.update(b"format")

    assert len(sha256.digest()) == 32
    assert len(sha256.hexdigest()) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", sha256.hexdigest())


def test_sha256_attributes():
    assert SHA256.block_size == 64
    assert SHA256.digest_size == 32
    assert SHA256.name == "sha256"


def test_sha256_keeps_only_incomplete_block_in_buffer():
    message = bytes((index * 13 + 7) % 256 for index in range(64 * 100 + 23))
    sha256 = SHA256()

    sha256.update(message)

    assert len(sha256._buffer) == 23
    assert len(sha256._buffer) < sha256.block_size
    assert sha256._length == len(message)
    assert sha256.digest() == hashlib.sha256(message).digest()
