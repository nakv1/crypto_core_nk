"""Дополнение PKCS#7 для 16-байтных блоков AES."""

BLOCK_SIZE = 16


class PaddingError(ValueError):
    """Ошибка некорректного дополнения PKCS#7."""


def pad(data: bytes) -> bytes:
    """Добавление дополнения PKCS#7."""
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length]) * padding_length


def unpad(data: bytes) -> bytes:
    """Проверка и удаление дополнения PKCS#7."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise PaddingError("padded data length must be a positive multiple of 16")

    padding_length = data[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise PaddingError("padding length byte is invalid")

    expected_padding = bytes([padding_length]) * padding_length
    if data[-padding_length:] != expected_padding:
        raise PaddingError("padding bytes are inconsistent")

    return data[:-padding_length]
