"""NIST AES_GCM.pdf, примеры AES-128 1–5, и независимый эталон."""

import random

import pytest
from Crypto.Cipher import AES

from cryptocore.aead import AuthenticationError
from cryptocore.aes import AES128
from cryptocore.modes import gcm

KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
NONCE = bytes.fromhex("cafebabefacedbaddecaf888")
PLAINTEXT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
AAD = bytes.fromhex(
    "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
    "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
CIPHERTEXT = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")


@pytest.mark.parametrize("length,aad,tag", [
    (0, b"", "3247184b3c4f69a44dbcd22887bbb418"),
    (64, b"", "4d5c2af327cd64a62cf35abd2ba6fab4"),
    (0, AAD, "5f91d77123ef5eb9997913849b8dc1e9"),
    (64, AAD, "64c0232904af398a5b67c10b53a5024d"),
    (60, AAD[:20], "f07c2528eea2fca1211f905e1b6a881b"),
])
def test_nist_examples(length, aad, tag):
    expected = CIPHERTEXT[:length] + bytes.fromhex(tag)
    assert gcm.encrypt(KEY, NONCE, PLAINTEXT[:length], aad) == expected
    assert gcm.decrypt(KEY, NONCE, expected, aad) == PLAINTEXT[:length]


@pytest.mark.parametrize("nonce_length", [1, 8, 12, 13, 16, 60])
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 60, 257])
@pytest.mark.parametrize("aad_length", [0, 1, 15, 16, 17, 20, 65])
def test_matches_independent_gcm(nonce_length, length, aad_length):
    nonce = bytes(range(nonce_length))
    plaintext = (bytes(range(256)) * 2)[:length]
    aad = bytes(range(aad_length))
    reference = AES.new(KEY, AES.MODE_GCM, nonce=nonce, mac_len=16)
    reference.update(aad)
    ciphertext, tag = reference.encrypt_and_digest(plaintext)
    actual = gcm.encrypt(KEY, nonce, plaintext, (aad[i:i+3] for i in range(0, len(aad), 3)))
    assert actual == ciphertext + tag
    assert gcm.decrypt(KEY, nonce, actual, aad) == plaintext


def test_table_multiplication_matches_bit_algorithm():
    random_source = random.Random(9235)
    for _ in range(30):
        h, x = random_source.getrandbits(128), random_source.getrandbits(128)
        state = gcm.GHASH(h.to_bytes(16, "big"))
        state.update(x.to_bytes(16, "big"))
        assert int.from_bytes(state.digest(), "big") == gcm.multiply_gf(x, h)
    assert gcm.multiply_gf(1 << 127, 37) == 37
    assert gcm.multiply_gf(0, (1 << 128) - 1) == 0


@pytest.mark.parametrize("chunk_size", [1, 3, 15, 16, 17, 8192])
def test_streaming_counter_and_authentication(chunk_size):
    data = bytes(range(256)) * 33 + b"end"
    state = gcm.GCMAuthenticator(KEY, NONCE, [AAD[:3], b"", AAD[3:]])
    counter = gcm.GCTR(state.aes, state.j0)
    fragments = []
    for i in range(0, len(data), chunk_size):
        part = counter.update(data[i:i+chunk_size])
        state.update(part)
        fragments.append(part)
    assert b"".join(fragments) + state.digest() == gcm.encrypt(KEY, NONCE, data, AAD)
    assert state.digest() == state.digest()
    with pytest.raises(ValueError, match="finalized"):
        state.update(b"x")


def test_inc32_wraps_without_changing_nonce_prefix():
    class RecordingAES:
        blocks = []

        def encrypt_block(self, block):
            self.blocks.append(block)
            return bytes(16)

    aes = RecordingAES()
    counter = gcm.GCTR(aes, NONCE + bytes.fromhex("fffffffe"))
    assert counter.update(bytes(32)) == bytes(32)
    assert aes.blocks == [NONCE + bytes.fromhex("ffffffff"), NONCE + bytes(4)]


def test_no_decryption_on_any_bit_tampering(monkeypatch):
    packet = gcm.GCM(KEY).encrypt(b"secret", AAD)

    def reject_decryption(*args):
        raise AssertionError("plaintext must not be computed")

    monkeypatch.setattr(gcm.GCTR, "update", reject_decryption)
    for index in range(len(packet) * 8):
        tampered = bytearray(packet)
        tampered[index // 8] ^= 1 << (index % 8)
        with pytest.raises(AuthenticationError):
            gcm.GCM(KEY).decrypt(tampered, AAD)
    with pytest.raises(AuthenticationError):
        gcm.GCM(KEY).decrypt(packet, AAD + b"x")
    with pytest.raises(AuthenticationError):
        gcm.GCM(bytes(16)).decrypt(packet, AAD)


def test_automatic_nonce_is_new_for_each_encryption():
    cipher = gcm.GCM(KEY)
    nonces = {cipher.encrypt(b"")[:12] for _ in range(1000)}
    assert len(nonces) == 1000


def test_nonstandard_nonce_packet_requires_explicit_nonce():
    nonce = b"nonce-of-another-length"
    packet = gcm.GCM(KEY, nonce).encrypt(PLAINTEXT, AAD)
    assert gcm.GCM(KEY, nonce).decrypt(packet, AAD) == PLAINTEXT
    with pytest.raises(AuthenticationError):
        gcm.GCM(KEY, b"x" * len(nonce)).decrypt(packet, AAD)


@pytest.mark.parametrize("length", [0, 1, 15])
def test_truncated_tag(length):
    with pytest.raises(AuthenticationError):
        gcm.decrypt(KEY, NONCE, bytes(length))


def test_length_limits(monkeypatch):
    monkeypatch.setattr(gcm, "MAX_DATA_BYTES", 16)
    monkeypatch.setattr(gcm, "MAX_AAD_BYTES", 12)
    with pytest.raises(ValueError, match="AAD"):
        gcm.encrypt(KEY, NONCE, b"", [b"a" * 8, b"b" * 5])
    with pytest.raises(ValueError, match="counter"):
        gcm.encrypt(KEY, NONCE, bytes(17))
    state = gcm.GCMAuthenticator(KEY, NONCE)
    state.update(bytes(16))
    with pytest.raises(ValueError, match="counter"):
        state.update(b"x")
    counter = gcm.GCTR(state.aes, state.j0)
    counter.update(bytes(16))
    with pytest.raises(ValueError, match="counter"):
        counter.update(b"x")


def test_invalid_parameters():
    for key in [b"", bytes(15), bytes(17)]:
        with pytest.raises(ValueError):
            gcm.GCM(key)
    with pytest.raises(ValueError):
        gcm.encrypt(KEY, b"", b"")
    with pytest.raises(TypeError):
        gcm.encrypt(KEY, NONCE, b"", ["text"])
    with pytest.raises(ValueError):
        AES128(KEY).encrypt_block(b"short")
