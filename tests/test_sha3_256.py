import hashlib
import re

import pytest

from cryptocore.hash import SHA3_256


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            b"",
            "a7ffc6f8bf1ed76651c14756a061d662f"
            "580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            b"abc",
            "3a985da74fe225b2045c172d6bd390bd8"
            "55f086e3e9d525b46bfe24511431532",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "41c0dba2a9d6240849100376a8235e2c"
            "82e1b9998a999e21db32dd97496d3376",
        ),
        (
            b"a" * 1_000_000,
            "5c8875ae474a3634ba4fd55ec85bffd66"
            "1f32aca75c6d699d0cdcb6c115891c1",
        ),
    ],
    ids=["empty", "abc", "long_message", "million_a"],
)
def test_sha3_256_known_answers(message, expected):
    sha3 = SHA3_256()
    sha3.update(message)

    assert sha3.hexdigest() == expected


@pytest.mark.parametrize("length", [0, 1, 134, 135, 136, 137, 271, 272, 273])
def test_sha3_256_padding_boundaries(length):
    message = bytes((index * 37 + 11) % 256 for index in range(length))
    sha3 = SHA3_256()
    sha3.update(message)

    assert sha3.digest() == hashlib.sha3_256(message).digest()


@pytest.mark.parametrize("length", [2, 17, 31, 257, 1000, 4097])
def test_sha3_256_deterministic_messages(length):
    message = bytes((index * 19 + length) % 256 for index in range(length))
    sha3 = SHA3_256()
    sha3.update(message)

    assert sha3.hexdigest() == hashlib.sha3_256(message).hexdigest()


@pytest.mark.parametrize(
    "chunk_size",
    [None, 1, 7, 136, 200],
    ids=["whole", "one", "seven", "rate", "two_hundred"],
)
def test_sha3_256_chunk_sizes_match_hashlib(chunk_size):
    message = bytes((index * 29 + 5) % 256 for index in range(4097))
    sha3 = SHA3_256()

    if chunk_size is None:
        sha3.update(message)
    else:
        for offset in range(0, len(message), chunk_size):
            sha3.update(message[offset : offset + chunk_size])

    assert sha3.digest() == hashlib.sha3_256(message).digest()


@pytest.mark.parametrize(
    "value",
    [
        b"bytes-like input",
        bytearray(b"bytes-like input"),
        memoryview(b"bytes-like input"),
    ],
)
def test_sha3_256_accepts_supported_bytes_like_types(value):
    sha3 = SHA3_256()
    sha3.update(value)

    assert sha3.digest() == hashlib.sha3_256(b"bytes-like input").digest()


@pytest.mark.parametrize("value", ["abc", 123, None, [1, 2, 3]])
def test_sha3_256_rejects_unsupported_types(value):
    with pytest.raises(TypeError, match="data must be bytes-like"):
        SHA3_256().update(value)


def test_sha3_256_empty_update_does_not_change_digest():
    sha3 = SHA3_256()
    sha3.update(b"abc")
    before = sha3.digest()

    assert sha3.update(b"") is None
    assert sha3.digest() == before


def test_sha3_256_update_returns_none():
    assert SHA3_256().update(b"abc") is None


def test_sha3_256_digest_and_hexdigest_are_repeatable_in_any_order():
    sha3 = SHA3_256()
    sha3.update(b"abc")
    expected_digest = hashlib.sha3_256(b"abc").digest()
    expected_hexdigest = hashlib.sha3_256(b"abc").hexdigest()

    assert sha3.digest() == expected_digest
    assert sha3.digest() == expected_digest
    assert sha3.hexdigest() == expected_hexdigest
    assert sha3.hexdigest() == expected_hexdigest
    assert sha3.digest() == expected_digest

    reverse_order = SHA3_256()
    reverse_order.update(b"abc")
    assert reverse_order.hexdigest() == expected_hexdigest
    assert reverse_order.digest() == expected_digest


def test_sha3_256_update_continues_after_digest_and_hexdigest():
    sha3 = SHA3_256()
    sha3.update(b"abc")
    assert sha3.digest() == hashlib.sha3_256(b"abc").digest()
    assert sha3.hexdigest() == hashlib.sha3_256(b"abc").hexdigest()

    sha3.update(b"def")

    assert sha3.digest() == hashlib.sha3_256(b"abcdef").digest()
    assert sha3.hexdigest() == hashlib.sha3_256(b"abcdef").hexdigest()


def test_sha3_256_result_sizes_and_hex_format():
    sha3 = SHA3_256()
    sha3.update(b"format")

    assert len(sha3.digest()) == 32
    assert len(sha3.hexdigest()) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", sha3.hexdigest())


def test_sha3_256_attributes():
    assert SHA3_256.block_size == 136
    assert SHA3_256.digest_size == 32
    assert SHA3_256.name == "sha3-256"


def test_sha3_256_keeps_only_incomplete_block_in_buffer():
    message = bytes((index * 13 + 7) % 256 for index in range(136 * 100 + 37))
    sha3 = SHA3_256()

    sha3.update(message)

    assert len(sha3._buffer) == 37
    assert len(sha3._buffer) < sha3.block_size
    assert sha3.digest() == hashlib.sha3_256(message).digest()
