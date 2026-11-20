import hmac
import io

import pytest

from cryptocore.cli import main


def arguments(path, key="00112233445566778899aabbccddeeff"):
    return ["dgst", "--hmac", "--key", key, "--input", str(path)]


@pytest.mark.parametrize("key_size", [0, 1, 16, 64, 100])
@pytest.mark.parametrize("data", [b"", b"message\x00\xff"])
def test_hmac_stdout(key_size, data, tmp_path, capsys):
    path = tmp_path / "input with spaces.bin"
    path.write_bytes(data)
    key = bytes(range(key_size))
    assert main(arguments(path, key.hex())) == 0
    captured = capsys.readouterr()
    assert captured.out == f"{hmac.digest(key, data, 'sha256').hex()} {path}\n"
    assert captured.err == ""


def test_hmac_output_and_stdin(tmp_path, monkeypatch, capsys):
    class Stdin:
        buffer = io.BytesIO(b"stdin message")

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())
    output = tmp_path / "mac.txt"
    output.write_text("old")
    key = bytes.fromhex("aa" * 100)
    assert main(arguments("-", key.hex()) + ["--output", str(output)]) == 0
    assert output.read_bytes() == f"{hmac.digest(key, b'stdin message', 'sha256').hex()} -\n".encode()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("extra", [
    ["--hmac"], ["--hmac", "--key", "xyz"],
    ["--hmac", "--key", "abc"], ["--hmac", "--key", "aa bb"],
    ["--hmac", "--key", "00", "--algorithm", "sha3-256"],
    ["--key", "00", "--algorithm", "sha256"],
])
def test_invalid_hmac_arguments(extra, tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(["dgst", "--input", str(tmp_path / "missing")] + extra)
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_hmac_input_error_preserves_output(tmp_path, capsys):
    output = tmp_path / "mac.txt"
    output.write_bytes(b"keep")
    assert main(arguments(tmp_path / "missing") + ["--output", str(output)]) == 1
    assert output.read_bytes() == b"keep"
    assert "error:" in capsys.readouterr().err


def test_hmac_explicit_sha256(tmp_path, capsys):
    path = tmp_path / "input"
    path.write_bytes(b"abc")
    assert main(arguments(path) + ["--algorithm", "sha256"]) == 0
    assert len(capsys.readouterr().out.split()[0]) == 64


@pytest.mark.parametrize("mac_flag", ["--hmac", "--cmac"])
def test_mac_reads_in_bounded_chunks(mac_flag, monkeypatch, capsys):
    data = bytes(range(256)) * 80
    sizes = []

    class Stream:
        def __init__(self):
            self.buffer = io.BytesIO(data)

        def read(self, size):
            assert 0 < size <= 8192
            sizes.append(size)
            return self.buffer.read(size)

    class Stdin:
        buffer = Stream()

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())
    command = arguments("-")
    command[1] = mac_flag
    assert main(command) == 0
    assert len(sizes) >= 3
    assert capsys.readouterr().err == ""


def test_partial_mac_read_failure_preserves_output(tmp_path, monkeypatch, capsys):
    output = tmp_path / "mac.txt"
    output.write_bytes(b"keep existing tag")

    class Stream:
        calls = 0

        def read(self, size):
            self.calls += 1
            if self.calls == 1:
                return b"first chunk"
            raise OSError("simulated read failure")

    class Stdin:
        buffer = Stream()

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())
    assert main(arguments("-") + ["--output", str(output)]) == 1
    assert output.read_bytes() == b"keep existing tag"
    assert "error:" in capsys.readouterr().err
