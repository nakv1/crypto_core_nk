"""Чтение и запись бинарных файлов."""

from pathlib import Path


def read_file(path: str | Path) -> bytes:
    """Чтение всего файла в виде байтов."""
    with Path(path).open("rb") as input_file:
        return input_file.read()


def write_file(path: str | Path, data: bytes) -> None:
    """Запись байтов в файл."""
    with Path(path).open("wb") as output_file:
        output_file.write(data)
