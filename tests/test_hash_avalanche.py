from statistics import mean

import pytest

from cryptocore.hash import SHA256, SHA3_256


MESSAGES = [
    b"a",
    b"abc",
    bytes(range(32)),
    bytes(range(256)),
    b"CryptoCore" * 20,
    bytes((index * 7 + 3) % 256 for index in range(1024)),
]

HASH_CLASSES = [SHA256, SHA3_256]


def _digest(hash_class, message):
    hash_object = hash_class()
    hash_object.update(message)
    return hash_object.digest()


def _changed_bits(hash_class, message):
    modified = bytearray(message)
    modified[0] ^= 0x01
    original_digest = _digest(hash_class, message)
    modified_digest = _digest(hash_class, modified)
    return sum(
        (original ^ changed).bit_count()
        for original, changed in zip(original_digest, modified_digest)
    )


@pytest.mark.parametrize("hash_class", HASH_CLASSES, ids=["sha256", "sha3_256"])
@pytest.mark.parametrize(
    "message",
    MESSAGES,
    ids=["a", "abc", "range_32", "range_256", "cryptocore", "pattern_1024"],
)
def test_hash_avalanche_for_each_message(hash_class, message):
    changed_bits = _changed_bits(hash_class, message)

    assert 100 < changed_bits < 156


@pytest.mark.parametrize("hash_class", HASH_CLASSES, ids=["sha256", "sha3_256"])
def test_hash_avalanche_average(hash_class):
    average = mean(_changed_bits(hash_class, message) for message in MESSAGES)

    assert 120 <= average <= 136
