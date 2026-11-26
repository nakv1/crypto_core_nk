import os
import subprocess
import sys
from pathlib import Path

import pytest
from Crypto.Cipher import AES

from cryptocore.aead.files import decrypt_file
from cryptocore.cli import main
from cryptocore.csprng import RandomGenerationError
from cryptocore.modes.gcm import GCM, GCTR

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
AAD = b"header"


def arguments(source, output=None, operation="--encrypt", extra=()):
    args = ["--algorithm", "aes", "--mode", "gcm", operation,
            "--key", KEY.hex(), "--input", str(source)]
    if output is not None:
        args += ["--output", str(output)]
    return args + list(extra)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 8191, 8192, 8193, 16411])
@pytest.mark.parametrize("aad_kind", ["default", "hex", "file"])
def test_cli_roundtrip_and_reference(size, aad_kind, tmp_path, capsys):
    source, encrypted, result = [tmp_path / name for name in ["plain file", "cipher", "result"]]
    plaintext = (bytes(range(256)) * 65)[:size]
    source.write_bytes(plaintext)
    if aad_kind == "file":
        aad_file = tmp_path / "aad.bin"
        aad_file.write_bytes(AAD)
        extra, aad = ["--aad-file", str(aad_file)], AAD
    elif aad_kind == "hex":
        extra, aad = ["--aad", AAD.hex()], AAD
    else:
        extra, aad = [], b""
    assert main(arguments(source, encrypted, extra=extra)) == 0
    packet = encrypted.read_bytes()
    assert len(packet) == size + 28
    reference = AES.new(KEY, AES.MODE_GCM, nonce=packet[:12])
    reference.update(aad)
    assert reference.decrypt_and_verify(packet[12:-16], packet[-16:]) == plaintext
    assert main(arguments(encrypted, result, "--decrypt", extra)) == 0
    assert result.read_bytes() == plaintext
    assert "[SUCCESS]" in capsys.readouterr().out


@pytest.mark.parametrize("tamper", ["nonce", "data", "tag", "aad", "key", "short", "truncated"])
@pytest.mark.parametrize("existing", [False, True])
def test_failure_preserves_destination_and_never_decrypts(tamper, existing, tmp_path, capsys, monkeypatch):
    source, output = tmp_path / "cipher", tmp_path / "result"
    packet = bytearray(GCM(KEY).encrypt(b"secret", AAD))
    extra = ["--aad", AAD.hex()]
    if tamper in {"nonce", "data", "tag"}:
        index = {"nonce": 0, "data": 12, "tag": -1}[tamper]
        packet[index] ^= 1
    elif tamper == "aad":
        extra = ["--aad", b"wrong".hex()]
    elif tamper == "key":
        extra += ["--key", bytes(range(16)).hex()]
    elif tamper == "short":
        packet = packet[:11]
    else:
        packet = packet[:-1]
    source.write_bytes(packet)
    if existing:
        output.write_bytes(b"original")

    def reject(*args):
        raise AssertionError("must not generate plaintext")

    monkeypatch.setattr(GCTR, "update", reject)
    assert main(arguments(source, output, "--decrypt", extra)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Authentication failed" in captured.err
    if existing:
        assert output.read_bytes() == b"original"
    else:
        assert not output.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == (["cipher", "result"] if existing else ["cipher"])


@pytest.mark.parametrize("flag", ["--iv", "--nonce"])
def test_external_nonce_uses_raw_ciphertext_and_tag(flag, tmp_path):
    source, output = tmp_path / "raw", tmp_path / "out"
    nonce = bytes(range(12))
    reference = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    reference.update(AAD)
    ciphertext, tag = reference.encrypt_and_digest(b"message")
    source.write_bytes(ciphertext + tag)
    assert main(arguments(source, output, "--decrypt", [flag, nonce.hex(), "--aad", AAD.hex()])) == 0
    assert output.read_bytes() == b"message"


@pytest.mark.parametrize("extra", [
    ["--aad", "0"], ["--aad", "wrong"], ["--aad", "00 00"],
    ["--aad", "0x00"], ["--aad", "00", "--aad-file", "file"],
    ["--iv", "00" * 12], ["--nonce", "00" * 12],
    ["--nonce", "00" * 11], ["--nonce", "00" * 16],
    ["--iv", "00" * 12, "--nonce", "00" * 12],
    ["--mode", "ctr", "--aad", ""], ["--mode", "cbc", "--aad-file", "file"],
    ["--mode", "cbc", "--nonce", "00" * 12],
])
def test_invalid_arguments(extra, tmp_path):
    output = tmp_path / "out"
    with pytest.raises(SystemExit) as error:
        main(arguments(tmp_path / "missing", output, extra=extra))
    assert error.value.code == 2
    assert not output.exists()


def test_automatic_key_and_filenames(tmp_path, capsys):
    source = tmp_path / "plain"
    source.write_bytes(b"hello")
    args = arguments(source)
    del args[5:7]  # --key и значение
    assert main(args) == 0
    key_hex = capsys.readouterr().out.strip().split()[-1]
    encrypted = Path(str(source) + ".enc")
    assert GCM(bytes.fromhex(key_hex)).decrypt(encrypted.read_bytes()) == b"hello"
    assert main(arguments(encrypted, operation="--decrypt", extra=["--key", key_hex])) == 0
    assert Path(str(encrypted) + ".dec").read_bytes() == b"hello"
    original = encrypted.read_bytes()
    assert main(args) == 1
    assert encrypted.read_bytes() == original


def test_io_and_csprng_errors_preserve_existing_file(tmp_path, monkeypatch):
    source, output = tmp_path / "plain", tmp_path / "out"
    source.write_bytes(b"hello")
    output.write_bytes(b"original")
    assert main(arguments(source, output, extra=["--aad-file", str(tmp_path / "missing")])) == 1
    assert main(arguments(tmp_path / "missing", output)) == 1

    def fail(size):
        raise RandomGenerationError("unavailable")

    monkeypatch.setattr("cryptocore.csprng.generate_random_bytes", fail)
    assert main(arguments(source, output)) == 1
    assert output.read_bytes() == b"original"
    assert {p.name for p in tmp_path.iterdir()} == {"plain", "out"}


def test_file_reads_are_bounded(tmp_path, monkeypatch):
    source, output = tmp_path / "plain", tmp_path / "out"
    source.write_bytes(b"data" * 5000)
    aad = tmp_path / "aad"
    aad.write_bytes(b"meta" * 3000)
    original_open = Path.open

    class Bounded:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            assert 0 < size <= 8192
            return self.stream.read(min(size, 13))

    def bounded_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return Bounded(stream) if mode == "rb" else stream

    monkeypatch.setattr(Path, "open", bounded_open)
    assert main(arguments(source, output, extra=["--aad-file", str(aad)])) == 0
    result = tmp_path / "result"
    assert main(arguments(output, result, "--decrypt", ["--aad-file", str(aad)])) == 0
    assert result.stat().st_size == 20000


def test_file_decryption_uses_authenticated_snapshot(tmp_path, monkeypatch):
    source, output = tmp_path / "cipher", tmp_path / "out"
    source.write_bytes(GCM(KEY).encrypt(b"original"))
    original_update = GCTR.update

    def replace_source(self, data):
        source.write_bytes(b"changed after verification")
        return original_update(self, data)

    monkeypatch.setattr(GCTR, "update", replace_source)
    decrypt_file(KEY, source, output)
    assert output.read_bytes() == b"original"


def test_write_failure_preserves_old_output_and_cleans_temporary(tmp_path, monkeypatch):
    source, output = tmp_path / "plain", tmp_path / "out"
    source.write_bytes(b"data")
    output.write_bytes(b"original")

    def fail(*args):
        raise OSError("simulated publication error")

    monkeypatch.setattr(os, "replace", fail)
    assert main(arguments(source, output)) == 1
    assert output.read_bytes() == b"original"
    assert len(list(tmp_path.iterdir())) == 2


def test_real_cli_authentication_failure_exit_code(tmp_path):
    source, output = tmp_path / "cipher", tmp_path / "out"
    source.write_bytes(GCM(KEY).encrypt(b"secret", AAD))
    result = subprocess.run([sys.executable, "-m", "cryptocore", *arguments(source, output, "--decrypt")],
                            capture_output=True, check=False)
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"Authentication failed" in result.stderr
    assert not output.exists()


def test_explicit_output_can_replace_input_after_success(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"original")
    assert main(arguments(path, path)) == 0
    assert main(arguments(path, path, "--decrypt")) == 0
    assert path.read_bytes() == b"original"


def test_exclusive_publication_race_preserves_competing_file(tmp_path, monkeypatch):
    source = tmp_path / "plain"
    source.write_bytes(b"hello")
    output = Path(str(source) + ".enc")
    original_link = os.link

    def race(temporary, destination):
        Path(destination).write_bytes(b"created by another process")
        original_link(temporary, destination)

    monkeypatch.setattr(os, "link", race)
    assert main(arguments(source)) == 1
    assert output.read_bytes() == b"created by another process"
    assert len(list(tmp_path.iterdir())) == 2


def test_aad_read_error_after_first_chunk_preserves_output(tmp_path, monkeypatch):
    source, output = tmp_path / "plain", tmp_path / "out"
    source.write_bytes(b"hello")
    output.write_bytes(b"original")

    def fail(path):
        yield b"first chunk"
        raise OSError("AAD read failed")

    monkeypatch.setattr("cryptocore.cli._file_aad", fail)
    assert main(arguments(source, output, extra=["--aad-file", "anything"])) == 1
    assert output.read_bytes() == b"original"
    assert len(list(tmp_path.iterdir())) == 2
