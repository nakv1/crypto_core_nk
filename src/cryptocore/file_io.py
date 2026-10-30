"""Чтение и запись бинарных файлов."""

from pathlib import Path


def iter_chunks(stream, chunk_size: int = 8192):
    """Последовательное чтение непустых частей потока."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    while True:
        chunk = stream.read(chunk_size)
        if chunk == b"":
            return
        yield chunk


def read_file(path: str | Path) -> bytes:
    """Чтение всего файла в виде байтов."""
    with Path(path).open("rb") as input_file:
        return input_file.read()


def write_file(path: str | Path, data: bytes) -> None:
    """Запись байтов в файл."""
    with Path(path).open("wb") as output_file:
        output_file.write(data)


def write_file_exclusive(path: str | Path, data: bytes) -> None:
    """Запись байтов только в новый файл с удалением при сбое записи."""
    output_path = Path(path)
    output_file = output_path.open("xb")

    try:
        with output_file:
            output_file.write(data)
    except Exception:
        try:
            output_path.unlink()
        except OSError:
            pass
        raise
