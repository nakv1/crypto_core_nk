"""Аутентифицированное шифрование; общий отказ без раскрытия причины."""


class AuthenticationError(ValueError):
    """Неверный ключ, AAD, nonce, шифртекст или тег."""


def aad_chunks(aad):
    """Принимает байты либо одноразовый итератор бинарных частей AAD."""
    if isinstance(aad, (bytes, bytearray, memoryview)):
        aad = (aad,)
    for chunk in aad:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("AAD chunks must be bytes-like")
        yield bytes(chunk)
