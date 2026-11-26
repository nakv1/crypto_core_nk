"""Encrypt-then-MAC: собственные AES-CTR и HMAC-SHA256.

Пакет: IV[16] || ciphertext || HMAC[32]. MAC покрывает версию схемы,
ключ AES, IV, ciphertext, AAD и две 64-битные длины в байтах. Фрейминг исключает
перенос байтов между ciphertext и AAD без изменения MAC.
"""

from secrets import compare_digest

from cryptocore import csprng
from cryptocore.aead import AuthenticationError, aad_chunks
from cryptocore.mac import HMAC
from cryptocore.modes import ctr

_DOMAIN = b"CryptoCore-EtM-CTR-HMAC-SHA256-v1\x00"


class EncryptThenMAC:
    """48 случайных байт материала: первые 16 для AES, остальные 32 для HMAC."""

    def __init__(self, key_material: bytes):
        if not isinstance(key_material, (bytes, bytearray, memoryview)):
            raise TypeError("key material must be bytes-like")
        if len(key_material) != 48:
            raise ValueError("EtM requires exactly 48 bytes of key material")
        self._encryption_key = bytes(key_material[:16])
        self._mac_key = bytes(key_material[16:])

    def _tag(self, body, aad):
        mac = HMAC(self._mac_key)
        mac.update(_DOMAIN)
        # Привязка к AES-части материала: её замена тоже вызывает отказ MAC.
        mac.update(self._encryption_key)
        mac.update(body)
        aad_length = 0
        for chunk in aad_chunks(aad):
            aad_length += len(chunk)
            if aad_length >= 1 << 64:
                raise ValueError("AAD is too long")
            mac.update(chunk)
        mac.update((len(body) - 16).to_bytes(8, "big"))
        mac.update(aad_length.to_bytes(8, "big"))
        return mac.digest()

    def encrypt(self, plaintext: bytes, aad=b"") -> bytes:
        """Генерирует новый IV при каждом вызове; возвращает полный пакет."""
        iv = csprng.generate_random_bytes(16)
        body = iv + ctr.encrypt(self._encryption_key, iv, plaintext)
        return body + self._tag(body, aad)

    def decrypt(self, packet: bytes, aad=b"") -> bytes:
        """Проверяет полный MAC до вызова расшифрования CTR."""
        packet = bytes(packet)
        if len(packet) < 48:
            raise AuthenticationError("authentication failed")
        body, tag = packet[:-32], packet[-32:]
        if not compare_digest(self._tag(body, aad), tag):
            raise AuthenticationError("authentication failed")
        return ctr.decrypt(self._encryption_key, body[:16], body[16:])
