"""Потоковая реализация SHA3-256 по FIPS 202."""

_MASK_64 = 0xFFFFFFFFFFFFFFFF

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

_ROTATION_OFFSETS = (
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
)


def _rotate_left(value: int, shift: int) -> int:
    """Циклический сдвиг 64-битного слова влево."""
    if shift == 0:
        return value & _MASK_64
    return ((value << shift) | (value >> (64 - shift))) & _MASK_64


class SHA3_256:
    """Потоковый SHA3-256 с повторяемой финализацией."""

    block_size = 136
    digest_size = 32
    name = "sha3-256"

    def __init__(self) -> None:
        self._state = [0] * 25
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

        offset = 0
        if self._buffer:
            needed = self.block_size - len(self._buffer)
            taken = min(needed, len(view))
            self._buffer.extend(view[:taken])
            offset = taken
            if len(self._buffer) == self.block_size:
                self._absorb_block(self._buffer)
                self._buffer.clear()

        full_end = offset + ((len(view) - offset) // self.block_size) * self.block_size
        while offset < full_end:
            self._absorb_block(view[offset : offset + self.block_size])
            offset += self.block_size

        if offset < len(view):
            self._buffer.extend(view[offset:])

    def digest(self) -> bytes:
        """Получение хеша без изменения рабочего состояния."""
        copy = self._copy()
        final_block = bytearray(copy.block_size)
        final_block[: len(copy._buffer)] = copy._buffer
        final_block[len(copy._buffer)] ^= 0x06
        final_block[-1] ^= 0x80
        copy._absorb_block(final_block)

        return b"".join(
            lane.to_bytes(8, "little") for lane in copy._state[:4]
        )

    def hexdigest(self) -> str:
        """Получение хеша как шестнадцатеричной строки."""
        return self.digest().hex()

    def _copy(self) -> "SHA3_256":
        """Копирование внутреннего состояния."""
        copy = SHA3_256()
        copy._state = self._state.copy()
        copy._buffer = self._buffer.copy()
        return copy

    def _absorb_block(self, block: bytes | bytearray | memoryview) -> None:
        """Поглощение одного 136-байтного блока."""
        for index in range(self.block_size // 8):
            start = index * 8
            lane = int.from_bytes(block[start : start + 8], "little")
            self._state[index] ^= lane
        self._keccak_f()

    def _keccak_f(self) -> None:
        """Перестановка Keccak-f[1600] из 24 раундов."""
        for round_constant in _ROUND_CONSTANTS:
            columns = [
                self._state[x]
                ^ self._state[x + 5]
                ^ self._state[x + 10]
                ^ self._state[x + 15]
                ^ self._state[x + 20]
                for x in range(5)
            ]
            differences = [
                columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1)
                for x in range(5)
            ]
            for y in range(5):
                for x in range(5):
                    index = x + 5 * y
                    self._state[index] ^= differences[x]

            rotated = [0] * 25
            for y in range(5):
                for x in range(5):
                    source = x + 5 * y
                    target = y + 5 * ((2 * x + 3 * y) % 5)
                    rotated[target] = _rotate_left(
                        self._state[source], _ROTATION_OFFSETS[source]
                    )

            for y in range(5):
                row = 5 * y
                for x in range(5):
                    self._state[row + x] = (
                        rotated[row + x]
                        ^ ((~rotated[row + (x + 1) % 5]) & rotated[row + (x + 2) % 5])
                    ) & _MASK_64

            self._state[0] ^= round_constant
