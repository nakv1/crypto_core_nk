"""Потоковая реализация SHA-256 по FIPS 180-4."""

_MASK_32 = 0xFFFFFFFF

_INITIAL_STATE = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_ROUND_CONSTANTS = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def _rotate_right(value: int, shift: int) -> int:
    """Циклический сдвиг 32-битного слова вправо."""
    return ((value >> shift) | (value << (32 - shift))) & _MASK_32


class SHA256:
    """Потоковый SHA-256 с повторяемой финализацией."""

    block_size = 64
    digest_size = 32
    name = "sha256"

    def __init__(self) -> None:
        self._state = list(_INITIAL_STATE)
        self._length = 0
        self._buffer = bytearray()

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Добавление очередной части сообщения."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        view = memoryview(data)
        if not view.contiguous:
            view = memoryview(view.tobytes())
        elif view.ndim != 1 or view.format != "B":
            view = view.cast("B")

        self._length += len(view)
        offset = 0

        if self._buffer:
            needed = self.block_size - len(self._buffer)
            taken = min(needed, len(view))
            self._buffer.extend(view[:taken])
            offset = taken
            if len(self._buffer) == self.block_size:
                self._process_block(self._buffer)
                self._buffer.clear()

        full_end = offset + ((len(view) - offset) // self.block_size) * self.block_size
        while offset < full_end:
            self._process_block(view[offset : offset + self.block_size])
            offset += self.block_size

        if offset < len(view):
            self._buffer.extend(view[offset:])

    def digest(self) -> bytes:
        """Получение хеша без изменения рабочего состояния."""
        copy = self._copy()
        bit_length = copy._length * 8
        zero_count = (56 - (copy._length + 1) % copy.block_size) % copy.block_size
        padding = b"\x80" + b"\x00" * zero_count + bit_length.to_bytes(8, "big")
        copy.update(padding)
        return b"".join(word.to_bytes(4, "big") for word in copy._state)

    def hexdigest(self) -> str:
        """Получение хеша как шестнадцатеричной строки."""
        return self.digest().hex()

    def _copy(self) -> "SHA256":
        """Копирование внутреннего состояния."""
        copy = SHA256()
        copy._state = self._state.copy()
        copy._length = self._length
        copy._buffer = self._buffer.copy()
        return copy

    def _process_block(self, block: bytes | bytearray | memoryview) -> None:
        """Сжатие одного 64-байтного блока."""
        words = [
            int.from_bytes(block[index : index + 4], "big")
            for index in range(0, self.block_size, 4)
        ]

        for index in range(16, 64):
            word_15 = words[index - 15]
            word_2 = words[index - 2]
            sigma_0 = (
                _rotate_right(word_15, 7)
                ^ _rotate_right(word_15, 18)
                ^ (word_15 >> 3)
            )
            sigma_1 = (
                _rotate_right(word_2, 17)
                ^ _rotate_right(word_2, 19)
                ^ (word_2 >> 10)
            )
            words.append(
                (
                    words[index - 16]
                    + sigma_0
                    + words[index - 7]
                    + sigma_1
                )
                & _MASK_32
            )

        a, b, c, d, e, f, g, h = self._state

        for constant, word in zip(_ROUND_CONSTANTS, words):
            big_sigma_1 = (
                _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            )
            choose = (e & f) ^ ((~e) & g)
            temp_1 = (h + big_sigma_1 + choose + constant + word) & _MASK_32
            big_sigma_0 = (
                _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            )
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp_2 = (big_sigma_0 + majority) & _MASK_32

            h = g
            g = f
            f = e
            e = (d + temp_1) & _MASK_32
            d = c
            c = b
            b = a
            a = (temp_1 + temp_2) & _MASK_32

        compressed = (a, b, c, d, e, f, g, h)
        self._state = [
            (current + value) & _MASK_32
            for current, value in zip(self._state, compressed)
        ]
