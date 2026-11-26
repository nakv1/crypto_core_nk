"""AES-128-GCM по NIST SP 800-38D: собственные GHASH и GCTR.

Низкоуровневые encrypt/decrypt принимают nonce отдельно и работают с C || T.
GCM — оболочка с форматом nonce || C || T. Явный nonce предназначен для
тестовых векторов и совместимости; его повторение с тем же ключом запрещено.
"""

from secrets import compare_digest

from cryptocore import csprng
from cryptocore.aead import AuthenticationError, aad_chunks
from cryptocore.aes import AES128

_R = 0xE1000000000000000000000000000000
MAX_DATA_BYTES = ((1 << 32) - 2) * 16
MAX_AAD_BYTES = ((1 << 64) - 1) // 8


def multiply_gf(x: int, y: int) -> int:
    """Базовый алгоритм 1 из SP 800-38D, в битовом представлении GHASH."""
    if not 0 <= x < 1 << 128 or not 0 <= y < 1 << 128:
        raise ValueError("field elements must be unsigned 128-bit integers")
    result = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= y
        y = (y >> 1) ^ (_R if y & 1 else 0)
    return result


class GHASH:
    """Потоковый GHASH, таблица 16 x 256 для фиксированного H."""

    def __init__(self, h: bytes):
        if len(h) != 16:
            raise ValueError("GHASH subkey must contain 16 bytes")
        self._tables = []
        v = int.from_bytes(h, "big")
        for _ in range(16):
            table = [0] * 256
            basis = {}
            for bit in range(7, -1, -1):
                basis[1 << bit] = v
                v = (v >> 1) ^ (_R if v & 1 else 0)
            for value in range(1, 256):
                low = value & -value
                table[value] = table[value ^ low] ^ basis[low]
            self._tables.append(table)
        self._value = 0
        self._buffer = b""

    def _block(self, block):
        encoded = (self._value ^ int.from_bytes(block, "big")).to_bytes(16, "big")
        value = 0
        for table, byte in zip(self._tables, encoded):
            value ^= table[byte]
        self._value = value

    def update(self, data):
        """Сохраняет не более 15 байт между вызовами."""
        data = self._buffer + bytes(data)
        end = len(data) - len(data) % 16
        for offset in range(0, end, 16):
            self._block(data[offset:offset + 16])
        self._buffer = data[end:]

    def pad(self):
        """Завершает отдельное поле нулевым дополнением до блока."""
        if self._buffer:
            self._block(self._buffer.ljust(16, b"\x00"))
            self._buffer = b""

    def digest(self):
        if self._buffer:
            raise ValueError("GHASH must be padded before digest")
        return self._value.to_bytes(16, "big")


def _j0(aes, nonce):
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")
    nonce = bytes(nonce)
    if not nonce or len(nonce) > MAX_AAD_BYTES:
        raise ValueError("nonce length is outside the GCM limits")
    if len(nonce) == 12:
        return nonce + b"\x00\x00\x00\x01"
    ghash = GHASH(aes.encrypt_block(bytes(16)))
    ghash.update(nonce)
    ghash.pad()
    ghash.update(bytes(8) + (len(nonce) * 8).to_bytes(8, "big"))
    return ghash.digest()


class GCTR:
    """Потоковый счётчик inc32; неполный блок продолжается следующим update."""

    def __init__(self, aes, j0):
        self._aes = aes
        self._prefix = j0[:12]
        self._counter = int.from_bytes(j0[12:], "big")
        self._tail = b""
        self._length = 0

    def update(self, data):
        if self._length + len(data) > MAX_DATA_BYTES:
            raise ValueError("GCM plaintext exceeds the counter limit")
        self._length += len(data)
        output = bytearray()
        offset = min(len(data), len(self._tail))
        output.extend(a ^ b for a, b in zip(data[:offset], self._tail[:offset]))
        self._tail = self._tail[offset:]
        while offset < len(data):
            self._counter = (self._counter + 1) & 0xFFFFFFFF
            stream = self._aes.encrypt_block(
                self._prefix + self._counter.to_bytes(4, "big")
            )
            part = data[offset:offset + 16]
            output.extend((int.from_bytes(part, "big") ^
                           int.from_bytes(stream[:len(part)], "big")).to_bytes(len(part), "big"))
            self._tail = stream[len(part):]
            offset += len(part)
        return bytes(output)


class GCMAuthenticator:
    """Вычисляет тег по AAD и ciphertext, не расшифровывая данные."""

    def __init__(self, key, nonce, aad=b""):
        self.aes = AES128(key)
        self.j0 = _j0(self.aes, nonce)
        self._ghash = GHASH(self.aes.encrypt_block(bytes(16)))
        self._aad_length = 0
        self._data_length = 0
        self._tag = None
        for chunk in aad_chunks(aad):
            self._aad_length += len(chunk)
            if self._aad_length > MAX_AAD_BYTES:
                raise ValueError("GCM AAD exceeds the length limit")
            self._ghash.update(chunk)
        self._ghash.pad()

    def update(self, ciphertext):
        if self._tag is not None:
            raise ValueError("GCM authentication is already finalized")
        if self._data_length + len(ciphertext) > MAX_DATA_BYTES:
            raise ValueError("GCM ciphertext exceeds the counter limit")
        self._data_length += len(ciphertext)
        self._ghash.update(ciphertext)

    def digest(self):
        if self._tag is None:
            self._ghash.pad()
            self._ghash.update((self._aad_length * 8).to_bytes(8, "big") +
                               (self._data_length * 8).to_bytes(8, "big"))
            mask = self.aes.encrypt_block(self.j0)
            self._tag = (int.from_bytes(mask, "big") ^
                         int.from_bytes(self._ghash.digest(), "big")).to_bytes(16, "big")
        return self._tag

    def verify(self, tag):
        if not compare_digest(self.digest(), tag):
            raise AuthenticationError("authentication failed")


def encrypt(key: bytes, nonce: bytes, data: bytes, aad=b"") -> bytes:
    """Возвращает ciphertext || tag[16]; nonce передаётся отдельно."""
    state = GCMAuthenticator(key, nonce, aad)
    ciphertext = GCTR(state.aes, state.j0).update(data)
    state.update(ciphertext)
    return ciphertext + state.digest()


def decrypt(key: bytes, nonce: bytes, data: bytes, aad=b"") -> bytes:
    """Проверяет тег до создания открытого текста; принимает ciphertext || tag."""
    if len(data) < 16:
        raise AuthenticationError("authentication failed")
    ciphertext, tag = data[:-16], data[-16:]
    state = GCMAuthenticator(key, nonce, aad)
    state.update(ciphertext)
    state.verify(tag)
    return GCTR(state.aes, state.j0).update(ciphertext)


class GCM:
    """Оболочка nonce || ciphertext || tag; автоматический nonce всегда новый.

    При явном nonce другой длины расшифрование пакета требует экземпляр
    с тем же явным nonce. В стандартном файловом формате nonce всегда 12 байт.
    """

    def __init__(self, key: bytes, nonce: bytes | None = None):
        aes = AES128(key)  # Проверяем ключ даже до первой операции.
        if nonce is not None:
            _j0(aes, nonce)
        self._key = bytes(key)
        self._fixed_nonce = None if nonce is None else bytes(nonce)
        self.nonce = self._fixed_nonce

    def encrypt(self, plaintext: bytes, aad=b"") -> bytes:
        self.nonce = (self._fixed_nonce if self._fixed_nonce is not None
                      else csprng.generate_random_bytes(12))
        return self.nonce + encrypt(self._key, self.nonce, plaintext, aad)

    def decrypt(self, packet: bytes, aad=b"") -> bytes:
        size = len(self._fixed_nonce) if self._fixed_nonce is not None else 12
        if len(packet) < size + 16:
            raise AuthenticationError("authentication failed")
        nonce = packet[:size]
        if self._fixed_nonce is not None and not compare_digest(nonce, self._fixed_nonce):
            raise AuthenticationError("authentication failed")
        return decrypt(self._key, nonce, packet[size:], aad)
