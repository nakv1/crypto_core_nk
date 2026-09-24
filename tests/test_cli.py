import pytest

from cryptocore.aes import encrypt_block
from cryptocore.cli import main


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
