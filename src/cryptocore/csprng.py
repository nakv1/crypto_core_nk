"""Криптографически стойкая генерация случайных байтов."""

import os


class RandomGenerationError(RuntimeError):
    """Ошибка системного источника случайности."""


def generate_random_bytes(num_bytes: int) -> bytes:
    """Генерация заданного количества случайных байтов через ОС."""
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be an integer")
    if num_bytes < 0:
        raise ValueError("num_bytes must be non-negative")

    try:
        return os.urandom(num_bytes)
    except (OSError, NotImplementedError) as exc:
        raise RandomGenerationError("failed to generate random bytes") from exc
