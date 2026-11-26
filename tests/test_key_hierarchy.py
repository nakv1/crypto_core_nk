import hmac

import pytest

from cryptocore.kdf import derive_key, pbkdf2_hmac_sha256
from cryptocore.kdf._validation import MAX_KEY_BYTES
from cryptocore.aead.etm import EncryptThenMAC
from cryptocore.modes.gcm import GCM


@pytest.mark.parametrize("length", range(1, 101))
def test_hierarchy_exact_counter_formula(length):
    master, context = bytes(range(32)), "назначение🔐\x00"
    expected = b"".join(hmac.digest(master, context.encode() + i.to_bytes(4, "big"), "sha256")
                        for i in range(1, (length + 31) // 32 + 1))[:length]
    assert derive_key(master, context, length) == expected
    assert derive_key(master, context, length) == derive_key(master, context, length)


@pytest.mark.parametrize("master", [b"", b"x", bytes(range(65)), bytearray(b"master"), memoryview(b"master")])
def test_context_separation(master):
    keys = {derive_key(master, context) for context in ["encryption", "authentication", "", "encryption\x00"]}
    assert len(keys) == 4


def test_counter_is_four_byte_big_endian_beyond_255():
    actual = derive_key(b"master", "context", 8193)
    expected = hmac.digest(b"master", b"context" + (257).to_bytes(4, "big"), "sha256")
    assert actual[8192:] == expected[:1]


def test_password_to_independent_aead_keys():
    master = pbkdf2_hmac_sha256("password", b"a random salt!!", 2)
    aes_key = derive_key(master, "encryption", 16)
    mac_key = derive_key(master, "authentication", 32)
    assert aes_key != mac_key[:16]
    gcm = GCM(aes_key)
    assert gcm.decrypt(gcm.encrypt(b"message", b"metadata"), b"metadata") == b"message"
    etm = EncryptThenMAC(aes_key + mac_key)
    assert etm.decrypt(etm.encrypt(b"message", b"metadata"), b"metadata") == b"message"


@pytest.mark.parametrize("length", [0, -1, True, 1.5, None, MAX_KEY_BYTES + 1])
def test_bad_length(length):
    with pytest.raises((TypeError, ValueError)):
        derive_key(b"master", "context", length)


@pytest.mark.parametrize("master,context", [(None, "context"), ("text", "context"), (b"master", b"bytes"), (b"master", None)])
def test_bad_types(master, context):
    with pytest.raises(TypeError):
        derive_key(master, context)
