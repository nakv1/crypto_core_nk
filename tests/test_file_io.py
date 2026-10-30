import io
from pathlib import Path

import pytest

from cryptocore.file_io import iter_chunks, write_file_exclusive


@pytest.mark.parametrize(
    ("data", "chunk_size"),
    [
        (b"", 8),
        (b"abcdefgh" * 3, 8),
        (b"abcdefgh" * 3 + b"xyz", 8),
        (bytes(range(100)), 17),
    ],
)
def test_iter_chunks_returns_all_data_in_bounded_chunks(data, chunk_size):
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size))

    assert b"".join(chunks) == data
    assert all(0 < len(chunk) <= chunk_size for chunk in chunks)


@pytest.mark.parametrize("chunk_size", [0, -1, -100])
def test_iter_chunks_rejects_non_positive_size(chunk_size):
    with pytest.raises(ValueError, match="chunk_size must be greater than zero"):
        list(iter_chunks(io.BytesIO(b"data"), chunk_size))


def test_iter_chunks_continues_after_short_reads():
    class ShortReadStream:
        def __init__(self):
            self.responses = iter([b"abc", b"de", b"fghijk", b""])
            self.read_sizes = []

        def read(self, size):
            self.read_sizes.append(size)
            return next(self.responses)

    stream = ShortReadStream()

    chunks = list(iter_chunks(stream, 8))

    assert chunks == [b"abc", b"de", b"fghijk"]
    assert b"".join(chunks) == b"abcdefghijk"
    assert stream.read_sizes == [8, 8, 8, 8]


def test_write_file_exclusive_creates_new_file(tmp_path):
    output_path = tmp_path / "output.bin"

    write_file_exclusive(output_path, b"new data")

    assert output_path.read_bytes() == b"new data"


def test_write_file_exclusive_does_not_modify_existing_file(tmp_path):
    output_path = tmp_path / "output.bin"
    original = b"existing data"
    output_path.write_bytes(original)

    with pytest.raises(FileExistsError):
        write_file_exclusive(output_path, b"replacement")

    assert output_path.read_bytes() == original


def test_write_file_exclusive_removes_file_after_write_error(tmp_path, monkeypatch):
    output_path = tmp_path / "output.bin"
    original_open = Path.open

    class FailingOutput:
        def __init__(self, path):
            self.file = original_open(path, "xb")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.file.close()

        def write(self, data):
            self.file.write(data[:1])
            raise OSError("simulated write error")

    def failing_open(path, mode):
        assert path == output_path
        assert mode == "xb"
        return FailingOutput(path)

    monkeypatch.setattr(Path, "open", failing_open)

    with pytest.raises(OSError, match="simulated write error"):
        write_file_exclusive(output_path, b"partial data")

    assert not output_path.exists()
