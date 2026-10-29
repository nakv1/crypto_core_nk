from pathlib import Path

import pytest

from cryptocore.file_io import write_file_exclusive


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
