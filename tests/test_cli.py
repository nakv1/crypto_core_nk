import pytest

from cryptocore.aes import encrypt_block
from cryptocore.cli import main
from cryptocore.modes.ecb import encrypt as encrypt_ecb


KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
KEY = bytes.fromhex(KEY_HEX)


def cli_arguments(operation, input_path, output_path, key=KEY_HEX):
    return [
        "--algorithm",
        "aes",
        "--mode",
        "ecb",
        operation,
        "--key",
        key,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
    ]


@pytest.mark.parametrize(
    "key",
    [
        "z" * 32,
        "2b7e151628aed2a6ab f7158809cf4f3c",
        "00" * 15,
    ],
)
def test_cli_rejects_invalid_key(key, tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(cli_arguments("--encrypt", tmp_path / "in.bin", tmp_path / "out.bin", key))

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_cli_rejects_conflicting_operations(tmp_path, capsys):
    arguments = cli_arguments("--encrypt", tmp_path / "in.bin", tmp_path / "out.bin")
    arguments.insert(arguments.index("--key"), "--decrypt")

    with pytest.raises(SystemExit) as error:
        main(arguments)

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_cli_rejects_missing_required_argument(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--algorithm", "aes"])

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_cli_reports_missing_input_file(tmp_path, capsys):
    output_path = tmp_path / "out.bin"

    result = main(cli_arguments("--encrypt", tmp_path / "missing.bin", output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == f"error: input file not found: {tmp_path / 'missing.bin'}\n"
    assert not output_path.exists()


def test_cli_reports_output_write_error(tmp_path, capsys):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    output_path = tmp_path / "missing" / "out.bin"

    result = main(cli_arguments("--encrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == f"error: output directory does not exist: {output_path}\n"
    assert not output_path.exists()


@pytest.mark.parametrize("ciphertext", [b"", b"x" * 15])
def test_cli_rejects_invalid_ciphertext_length_without_output(
    ciphertext, tmp_path, capsys
):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    input_path.write_bytes(ciphertext)

    result = main(cli_arguments("--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ciphertext length")
    assert not output_path.exists()


def test_cli_rejects_invalid_padding_without_output(tmp_path, capsys):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    invalid_padded_block = b"A" * 15 + b"\x00"
    input_path.write_bytes(encrypt_block(KEY, invalid_padded_block))

    result = main(cli_arguments("--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "error: invalid padding (wrong key or corrupted data)\n"
    assert not output_path.exists()


def test_cli_does_not_modify_existing_output_on_crypto_error(tmp_path, capsys):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    original_output = b"keep this existing file"
    input_path.write_bytes(b"x" * 15)
    output_path.write_bytes(original_output)

    result = main(cli_arguments("--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ciphertext length")
    assert output_path.read_bytes() == original_output


@pytest.mark.parametrize(
    "original",
    [
        "CryptoCore test text".encode("utf-8"),
        bytes([0x00, 0xFF, 0x10, 0x80]) * 23,
    ],
)
def test_cli_encrypt_decrypt_round_trip(original, tmp_path, capsys):
    input_path = tmp_path / "original.bin"
    encrypted_path = tmp_path / "encrypted.bin"
    decrypted_path = tmp_path / "decrypted.bin"
    input_path.write_bytes(original)

    encrypt_result = main(
        cli_arguments("--encrypt", input_path, encrypted_path)
    )
    decrypt_result = main(
        cli_arguments("--decrypt", encrypted_path, decrypted_path)
    )

    captured = capsys.readouterr()
    assert encrypt_result == 0
    assert decrypt_result == 0
    assert captured.out == ""
    assert captured.err == ""
    assert decrypted_path.read_bytes() == original


def test_cli_allows_same_input_and_output_path(tmp_path):
    path = tmp_path / "data.bin"
    original = b"same path is allowed"
    path.write_bytes(original)

    assert main(cli_arguments("--encrypt", path, path)) == 0
    assert path.read_bytes() != original
    assert main(cli_arguments("--decrypt", path, path)) == 0
    assert path.read_bytes() == original


def automatic_output_arguments(operation, input_path):
    return [
        "--algorithm",
        "aes",
        "--mode",
        "ecb",
        operation,
        "--key",
        KEY_HEX,
        "--input",
        str(input_path),
    ]


def test_cli_encrypt_without_output_uses_enc_suffix(tmp_path):
    input_path = tmp_path / "message.bin"
    output_path = tmp_path / "message.bin.enc"
    input_path.write_bytes(b"automatic encryption output")

    result = main(automatic_output_arguments("--encrypt", input_path))

    assert result == 0
    assert output_path.is_file()
    assert output_path.read_bytes() != input_path.read_bytes()


def test_cli_decrypt_without_output_uses_dec_suffix(tmp_path):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "ciphertext.bin.dec"
    plaintext = b"automatic decryption output"
    input_path.write_bytes(encrypt_ecb(KEY, plaintext))

    result = main(automatic_output_arguments("--decrypt", input_path))

    assert result == 0
    assert output_path.read_bytes() == plaintext


def test_cli_round_trip_with_automatic_output_names(tmp_path):
    input_path = tmp_path / "original.bin"
    encrypted_path = tmp_path / "original.bin.enc"
    decrypted_path = tmp_path / "original.bin.enc.dec"
    original = b"round trip with automatic names"
    input_path.write_bytes(original)

    encrypt_result = main(automatic_output_arguments("--encrypt", input_path))
    decrypt_result = main(automatic_output_arguments("--decrypt", encrypted_path))

    assert encrypt_result == 0
    assert decrypt_result == 0
    assert decrypted_path.read_bytes() == original


def test_cli_rejects_existing_automatic_output_without_numbering(tmp_path, capsys):
    input_path = tmp_path / "message.bin"
    output_path = tmp_path / "message.bin.enc"
    numbered_path = tmp_path / "message.bin.enc.1"
    original_output = b"existing output must stay unchanged"
    input_path.write_bytes(b"new plaintext")
    output_path.write_bytes(original_output)

    result = main(automatic_output_arguments("--encrypt", input_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert output_path.read_bytes() == original_output
    assert not numbered_path.exists()


def test_cli_does_not_create_automatic_output_on_crypto_error(tmp_path, capsys):
    input_path = tmp_path / "broken.bin"
    output_path = tmp_path / "broken.bin.dec"
    input_path.write_bytes(b"not a complete AES block")

    result = main(automatic_output_arguments("--decrypt", input_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error:")
    assert not output_path.exists()


def test_cli_preserves_file_created_during_automatic_output_race(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "message.bin"
    output_path = tmp_path / "message.bin.enc"
    raced_output = b"created by another process"
    input_path.write_bytes(b"plaintext")

    def raise_file_exists(path, data):
        assert path == str(output_path)
        assert data
        output_path.write_bytes(raced_output)
        raise FileExistsError

    monkeypatch.setattr("cryptocore.cli.write_file_exclusive", raise_file_exists)

    result = main(automatic_output_arguments("--encrypt", input_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert output_path.read_bytes() == raced_output


def test_cli_reports_automatic_output_write_error(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "message.bin"
    output_path = tmp_path / "message.bin.enc"
    input_path.write_bytes(b"plaintext")

    def raise_write_error(path, data):
        assert path == str(output_path)
        assert data
        raise OSError("simulated write error")

    monkeypatch.setattr("cryptocore.cli.write_file_exclusive", raise_write_error)

    result = main(automatic_output_arguments("--encrypt", input_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == f"error: cannot write output file: {output_path}\n"
    assert not output_path.exists()
