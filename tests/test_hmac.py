import hashlib
import hmac

import pytest

from cryptocore.mac import HMAC


# RFC 4231, разделы 4.2–4.5, 4.7–4.8: полные 256-битные ответы.
@pytest.mark.parametrize(("key", "data", "expected"), [
    (b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    (b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than "
     b"block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
])
def test_rfc4231(key, data, expected):
    mac = HMAC(key, "sha256")
    mac.update(data)
    assert mac.hexdigest() == expected
    assert mac.compute(data) == expected


def test_rfc4231_truncated_vector():
    mac = HMAC(b"\x0c" * 20)
    mac.update(b"Test With Truncation")
    assert mac.digest()[:16].hex() == "a3b6167473100ee06e0c796c2955552b"


@pytest.mark.parametrize("key_size", [0, 1, 16, 32, 63, 64, 65, 100, 131])
@pytest.mark.parametrize("data_size", [0, 1, 55, 56, 64, 65, 1000])
def test_key_and_message_boundaries(key_size, data_size):
    key = bytes(range(key_size))
    data = bytes(i % 256 for i in range(data_size))
    mac = HMAC(key)
    mac.update(data)
    assert mac.digest() == hmac.digest(key, data, "sha256")


@pytest.mark.parametrize("chunk_size", [1, 7, 64, 8192])
def test_streaming_repeatable_finalization(chunk_size):
    data = bytes(range(256)) * 70
    mac = HMAC(b"streaming key")
    for start in range(0, len(data), chunk_size):
        mac.update(data[start:start + chunk_size])
    expected = hmac.new(b"streaming key", data, hashlib.sha256).hexdigest()
    assert mac.hexdigest() == expected
    assert mac.hexdigest() == expected
    assert len(mac._inner._buffer) < 64
    mac.update(b"more")
    assert mac.hexdigest() == hmac.digest(b"streaming key", data + b"more", "sha256").hex()


def test_compute_does_not_modify_stream():
    mac = HMAC(b"key")
    mac.update(b"first")
    assert mac.compute(b"second") == hmac.digest(b"key", b"second", "sha256").hex()
    assert mac.digest() == hmac.digest(b"key", b"first", "sha256")


@pytest.mark.parametrize("key", [b"key", bytearray(b"key"), memoryview(b"key")])
def test_bytes_like_keys(key):
    assert HMAC(key).compute(b"data") == hmac.digest(b"key", b"data", "sha256").hex()


@pytest.mark.parametrize("bad", [None, 42, "key", [1, 2]])
def test_invalid_key_type(bad):
    with pytest.raises(TypeError, match="key must be bytes-like"):
        HMAC(bad)


def test_invalid_hash():
    with pytest.raises(ValueError, match="only sha256"):
        HMAC(b"key", "sha3-256")


def test_invalid_data_type():
    with pytest.raises(TypeError, match="data must be bytes-like"):
        HMAC(b"key").update("text")
