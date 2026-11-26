import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from cryptocore.cli import main
from cryptocore.csprng import RandomGenerationError


def arguments(extra=()):
    return ["derive", "--password", "password", "--salt", "73616c74", "--iterations", "2", *extra]


def test_cli_exact_output(capsys):
    assert main(arguments()) == 0
    captured = capsys.readouterr()
    expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2).hex()
    assert captured.out == expected + "  73616c74\n"
    assert captured.err == ""


def test_defaults_and_random_salt(monkeypatch, capsys):
    seen = []

    def random_bytes(size):
        seen.append(size)
        return bytes(range(size))

    def derive(password, salt, iterations, length):
        assert password == b"password"
        assert salt == bytes(range(16))
        assert (iterations, length) == (100000, 32)
        return b"k" * length

    monkeypatch.setattr("cryptocore.cli.csprng.generate_random_bytes", random_bytes)
    monkeypatch.setattr("cryptocore.cli.pbkdf2_hmac_sha256", derive)
    assert main(["derive", "--password", "password"]) == 0
    assert seen == [16]
    assert capsys.readouterr().out == (b"k" * 32).hex() + "  " + bytes(range(16)).hex() + "\n"


def test_one_thousand_automatic_salts(capsys):
    salts = set()
    for _ in range(1000):
        assert main(["derive", "--password", "p", "--iterations", "1", "--length", "1"]) == 0
        line = capsys.readouterr().out.strip()
        key, salt = line.split("  ")
        assert len(key) == 2 and len(salt) == 32
        salts.add(salt)
    assert len(salts) == 1000


@pytest.mark.parametrize("kind", ["argument", "file", "environment"])
def test_password_sources_preserve_exact_bytes(kind, tmp_path, monkeypatch, capsys):
    text = "пароль🔐\n"
    password = text.encode()
    if kind == "argument":
        source = ["--password", text]
    elif kind == "file":
        path = tmp_path / "password file"
        path.write_bytes(password + b"\x00")
        password += b"\x00"
        source = ["--password-file", str(path)]
    else:
        monkeypatch.setenv("CRYPTOCORE_TEST_PASSWORD", text)
        source = ["--password-env", "CRYPTOCORE_TEST_PASSWORD"]
    assert main(["derive", *source, "--salt", "", "--iterations", "1", "--length", "17"]) == 0
    expected = hashlib.pbkdf2_hmac("sha256", password, b"", 1, 17).hex()
    assert capsys.readouterr().out == expected + "  \n"
    if kind == "environment":
        assert os.environ["CRYPTOCORE_TEST_PASSWORD"] == text


def test_output_is_raw_key_without_salt(tmp_path, capsys):
    output = tmp_path / "key file"
    output.write_bytes(b"original")
    assert main(arguments(["--length", "17", "--output", str(output)])) == 0
    expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2, 17)
    assert output.read_bytes() == expected
    assert capsys.readouterr().out == expected.hex() + "  73616c74\n"


@pytest.mark.parametrize("extra", [
    ["--iterations", "0"], ["--iterations", "-1"], ["--iterations", "1.5"],
    ["--length", "0"], ["--length", "-1"], ["--length", "137438953441"],
    ["--salt", "0"], ["--salt", "0x00"], ["--salt", "00 00"], ["--salt", "xyz"],
    ["--algorithm", "sha256"], ["--password-file", "path"], ["--password-env", "NAME"],
])
def test_bad_arguments_do_not_create_output(extra, tmp_path):
    output = tmp_path / "key"
    with pytest.raises(SystemExit) as error:
        main(arguments([*extra, "--output", str(output)]))
    assert error.value.code == 2
    assert not output.exists()


def test_password_is_required():
    with pytest.raises(SystemExit) as error:
        main(["derive", "--iterations", "1"])
    assert error.value.code == 2


def test_empty_password_and_uppercase_salt(capsys):
    assert main(["derive", "--password", "", "--salt", "AABB", "--iterations", "1"]) == 0
    expected = hashlib.pbkdf2_hmac("sha256", b"", bytes.fromhex("aabb"), 1).hex()
    assert capsys.readouterr().out == expected + "  aabb\n"


def test_missing_password_sources_preserve_output(tmp_path, monkeypatch, capsys):
    output = tmp_path / "key"
    output.write_bytes(b"original")
    monkeypatch.delenv("CRYPTOCORE_MISSING_PASSWORD", raising=False)
    for source in [["--password-file", str(tmp_path / "missing")],
                   ["--password-env", "CRYPTOCORE_MISSING_PASSWORD"]]:
        assert main(["derive", *source, "--output", str(output), "--iterations", "1"]) == 1
        assert capsys.readouterr().out == ""
        assert output.read_bytes() == b"original"


@pytest.mark.parametrize("failure", ["random", "publication"])
def test_runtime_failures_preserve_old_key(failure, tmp_path, monkeypatch, capsys):
    output = tmp_path / "key"
    output.write_bytes(b"original")

    def fail(*args):
        if failure == "random":
            raise RandomGenerationError("source unavailable")
        raise OSError("cannot publish")

    monkeypatch.setattr("cryptocore.csprng.generate_random_bytes" if failure == "random" else "os.replace", fail)
    args = ["derive", "--password", "password", "--iterations", "1", "--output", str(output)]
    assert main(args) == 1
    assert capsys.readouterr().out == ""
    assert output.read_bytes() == b"original"
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize("failure", [False, True])
def test_owned_password_buffer_is_cleared_on_success_and_failure(failure, monkeypatch, capsys):
    captured = []

    def derive(password, salt, iterations, length):
        captured.append(password)
        assert password == b"password"
        if failure:
            raise ValueError("simulated failure")
        return bytes(length)

    monkeypatch.setattr("cryptocore.cli.pbkdf2_hmac_sha256", derive)
    assert main(arguments()) == (1 if failure else 0)
    assert captured == [bytearray(8)]
    if failure:
        assert capsys.readouterr().out == ""


def test_real_cli_entry_point(tmp_path):
    password_file = tmp_path / "password"
    password_file.write_bytes(b"pass\x00word\n")
    output = tmp_path / "key"
    result = subprocess.run([sys.executable, "-m", "cryptocore", "derive", "--password-file", str(password_file),
                             "--salt", "73616c74", "--iterations", "2", "--output", str(output)],
                            capture_output=True, text=True, check=False)
    expected = hashlib.pbkdf2_hmac("sha256", password_file.read_bytes(), b"salt", 2)
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected.hex() + "  73616c74\n"
    assert output.read_bytes() == expected
