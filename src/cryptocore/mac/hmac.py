"""Потоковый HMAC-SHA256 по RFC 2104."""

from cryptocore.hash import SHA256


class HMAC:
    """HMAC на собственной SHA-256, с ключом произвольной длины."""

    block_size = 64
    digest_size = 32
    name = "hmac-sha256"

    def __init__(self, key: bytes, hash_function: str = "sha256") -> None:
        if hash_function != "sha256":
            raise ValueError("HMAC supports only sha256")
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        key = bytes(key)
        if len(key) > self.block_size:
            key_hash = SHA256()
            key_hash.update(key)
            key = key_hash.digest()
        key = key.ljust(self.block_size, b"\x00")
        self._inner = SHA256()
        self._inner.update(bytes(byte ^ 0x36 for byte in key))
        self._outer_pad = bytes(byte ^ 0x5C for byte in key)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Добавляет часть сообщения без накопления файла в памяти."""
        self._inner.update(data)

    def digest(self) -> bytes:
        """Возвращает MAC без изменения состояния сообщения."""
        outer = SHA256()
        outer.update(self._outer_pad)
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        """Возвращает полный 256-битный MAC в нижнем регистре."""
        return self.digest().hex()

    def compute(self, message: bytes | bytearray | memoryview) -> str:
        """Однократно вычисляет MAC отдельного сообщения с тем же ключом."""
        inner = SHA256()
        # Восстанавливаем ipad из opad: (K xor 5c) xor 5c xor 36.
        inner.update(bytes(byte ^ 0x6A for byte in self._outer_pad))
        inner.update(message)
        outer = SHA256()
        outer.update(self._outer_pad)
        outer.update(inner.digest())
        return outer.hexdigest()
