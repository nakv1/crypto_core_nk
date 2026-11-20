import hmac
import subprocess
import sys

import pytest

from cryptocore.cli import main
from cryptocore.mac.verification import MAX_RECORD_SIZE, read_expected_mac


KEY = bytes(range(32))


def args(path):
    return ["dgst", "--hmac", "--key", KEY.hex(), "--input", str(path)]


@pytest.mark.parametrize("change", [None, "file", "key", "tag"])
def test_generate_then_verify(change, tmp_path, capsys):
    data = tmp_path / "input file.bin"
    tag = tmp_path / "expected.txt"
    data.write_bytes(b"original message\x00\xff")
    assert main(args(data) + ["--output", str(tag)]) == 0
    command = args(data) + ["--verify", str(tag)]
    if change == "file":
        original = data.read_bytes()
        data.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    elif change == "key":
        command[command.index("--key") + 1] = (bytes([KEY[0] ^ 1]) + KEY[1:]).hex()
    elif change == "tag":
        content = tag.read_text()
        tag.write_text(("0" if content[0] != "0" else "1") + content[1:])
    before = tag.read_bytes()
    assert main(command) == (0 if change is None else 1)
    captured = capsys.readouterr()
    assert ("[OK] HMAC verification successful" in captured.out) == (change is None)
    assert ("[ERROR] HMAC verification failed" in captured.err) == (change is not None)
    assert tag.read_bytes() == before


@pytest.mark.parametrize("record", [
    "{tag} input.bin\n", "\n  {tag}    ignored name.bin  \r\n\n",
    "\ufeff{tag}\tother-name.bin\n", "{tag}",
])
def test_flexible_expected_record(record, tmp_path):
    expected = hmac.digest(KEY, b"data", "sha256")
    path = tmp_path / "mac.txt"
    path.write_text(record.format(tag=expected.hex().upper()), encoding="utf-8")
    assert read_expected_mac(path, 32) == expected


@pytest.mark.parametrize("record", [
    b"", b"  \n", b"00 file", b"a" * 63, b"a" * 65,
    b"g" * 64, b"a" * 64 + b" file\n" + b"b" * 64 + b" other\n",
    b"a" * (MAX_RECORD_SIZE + 1), b"\xff\xfe",
], ids=["empty", "blank", "short", "63hex", "65hex", "badhex", "multiple", "oversized", "encoding"])
def test_malformed_expected_file(record, tmp_path, capsys):
    data = tmp_path / "input"
    data.write_bytes(b"abc")
    path = tmp_path / "expected"
    path.write_bytes(record)
    assert main(args(data) + ["--verify", str(path)]) == 1
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert captured.out == ""
    assert path.read_bytes() == record


def test_missing_expected_file(tmp_path, capsys):
    data = tmp_path / "input"
    data.write_bytes(b"abc")
    assert main(args(data) + ["--verify", str(tmp_path / "missing")]) == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("command", [
    ["dgst", "--algorithm", "sha256", "--input", "missing", "--verify", "expected"],
    ["dgst", "--hmac", "--key", "00", "--input", "missing", "--verify", "expected", "--output", "out"],
])
def test_invalid_verification_arguments(command, capsys):
    with pytest.raises(SystemExit) as error:
        main(command)
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_real_cli_exit_codes(tmp_path):
    data = tmp_path / "input"
    tag = tmp_path / "expected"
    data.write_bytes(b"abc")
    tag.write_text(hmac.digest(KEY, b"abc", "sha256").hex() + " ignored")
    command = [sys.executable, "-m", "cryptocore"] + args(data) + ["--verify", str(tag)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "verification successful" in result.stdout
    data.write_bytes(b"abd")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "verification failed" in result.stderr
