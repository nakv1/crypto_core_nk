import hashlib
import hmac

import pytest
from Crypto.Cipher import AES

from cryptocore.aead import AuthenticationError
from cryptocore.aead.etm import EncryptThenMAC
from cryptocore.modes import ctr

KEY = bytes(range(48))


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100, 8193])
@pytest.mark.parametrize("aad", [b"", b"metadata", bytes(range(65))])
def test_etm_matches_independent_composition(size, aad):
    plaintext = b"x" * size
    cipher = EncryptThenMAC(KEY)
    packet = cipher.encrypt(plaintext, iter([aad[:3], aad[3:]]))
    iv, body, tag = packet[:16], packet[16:-32], packet[-32:]
    reference = AES.new(KEY[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    assert reference.encrypt(plaintext) == body
    framed = (b"CryptoCore-EtM-CTR-HMAC-SHA256-v1\x00" + KEY[:16] + packet[:-32] + aad +
              size.to_bytes(8, "big") + len(aad).to_bytes(8, "big"))
    assert tag == hmac.new(KEY[16:], framed, hashlib.sha256).digest()
    assert cipher.decrypt(packet, aad) == plaintext


def test_etm_checks_authentication_before_decrypting(monkeypatch):
    cipher = EncryptThenMAC(KEY)
    packet = cipher.encrypt(b"secret", b"aad")

    def reject(*args):
        raise AssertionError("must not decrypt before successful verification")

    monkeypatch.setattr(ctr, "decrypt", reject)
    for bit in range(len(packet) * 8):
        tampered = bytearray(packet)
        tampered[bit // 8] ^= 1 << (bit % 8)
        with pytest.raises(AuthenticationError):
            cipher.decrypt(tampered, b"aad")
    for wrong_key in [bytes([1]) + KEY[1:], KEY[:16] + bytes(32)]:
        with pytest.raises(AuthenticationError):
            EncryptThenMAC(wrong_key).decrypt(packet, b"aad")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(packet, b"other")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(packet[:47], b"aad")


def test_etm_authenticates_field_boundaries():
    cipher = EncryptThenMAC(KEY)
    packet = cipher.encrypt(b"secret", b"abc")
    # Без длин MAC(C || AAD) не заметил бы перенос первого байта AAD в C.
    with pytest.raises(AuthenticationError):
        cipher.decrypt(packet[:-32] + b"a" + packet[-32:], b"bc")


def test_etm_generates_unique_ivs():
    cipher = EncryptThenMAC(KEY)
    assert len({cipher.encrypt(b"")[:16] for _ in range(1000)}) == 1000


@pytest.mark.parametrize("size", [0, 16, 32, 47, 49])
def test_key_material_must_have_independent_parts(size):
    with pytest.raises(ValueError):
        EncryptThenMAC(bytes(size))
