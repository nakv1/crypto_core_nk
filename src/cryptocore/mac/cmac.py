"""Потоковый AES-128-CMAC по NIST SP 800-38B."""

from cryptocore.aes import encrypt_block


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _double(block):
    """Умножение на x в GF(2^128), полином x^128+x^7+x^2+x+1."""
    value = int.from_bytes(block, "big")
    reduction = 0x87 if value >> 127 else 0
    return (((value << 1) & ((1 << 128) - 1)) ^ reduction).to_bytes(16, "big")


class CMAC:
    """CMAC с одним отложенным блоком для корректной финализации."""

    block_size = 16
    digest_size = 16
    name = "aes-128-cmac"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        self._key = bytes(key)
        if len(self._key) != 16:
            raise ValueError("AES-CMAC key must be exactly 16 bytes")
        self._k1 = _double(encrypt_block(self._key, bytes(16)))
        self._k2 = _double(self._k1)
        self._state = bytes(16)
        self._buffer = bytearray()

    def _consume(self, block) -> None:
        self._state = encrypt_block(self._key, _xor(self._state, block))

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Обрабатывает все блоки, кроме потенциально последнего."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        view = memoryview(data)
        if not view.contiguous:
            view = memoryview(view.tobytes())
        elif view.ndim != 1 or view.format != "B":
            view = view.cast("B")
        if not view:
            return
        offset = 0
        if self._buffer:
            taken = min(16 - len(self._buffer), len(view))
            self._buffer.extend(view[:taken])
            offset = taken
            if len(self._buffer) == 16 and offset < len(view):
                self._consume(self._buffer)
                self._buffer.clear()
        remaining = len(view) - offset
        end = offset + ((remaining - 1) // 16) * 16 if remaining else offset
        while offset < end:
            self._consume(view[offset:offset + 16])
            offset += 16
        self._buffer.extend(view[offset:])

    def digest(self) -> bytes:
        """Получает полный 128-битный MAC без изменения состояния."""
        if len(self._buffer) == 16:
            last = _xor(self._buffer, self._k1)
        else:
            padded = bytes(self._buffer) + b"\x80" + bytes(15 - len(self._buffer))
            last = _xor(padded, self._k2)
        return encrypt_block(self._key, _xor(self._state, last))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes | bytearray | memoryview) -> str:
        """Однократное вычисление MAC отдельного сообщения."""
        mac = CMAC(self._key)
        mac.update(message)
        return mac.hexdigest()
