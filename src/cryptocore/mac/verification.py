"""Разбор одного сохранённого MAC с ограничением размера файла."""

from pathlib import Path

MAX_RECORD_SIZE = 65536


def read_expected_mac(path: str | Path, digest_size: int) -> bytes:
    """Читает MAC, игнорируя имя файла, пустые строки и пробелы."""
    with Path(path).open("r", encoding="utf-8-sig") as source:
        text = source.read(MAX_RECORD_SIZE + 1)
    if len(text) > MAX_RECORD_SIZE:
        raise ValueError("MAC file is too large")
    records = [line.strip() for line in text.splitlines() if line.strip()]
    if len(records) != 1:
        raise ValueError("MAC file must contain exactly one non-empty record")
    token = records[0].split(maxsplit=1)[0]
    if len(token) != digest_size * 2 or any(c not in "0123456789abcdefABCDEF" for c in token):
        raise ValueError(f"expected MAC must contain exactly {digest_size * 2} hexadecimal characters")
    return bytes.fromhex(token)
