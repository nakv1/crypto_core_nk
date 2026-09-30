import pytest

from cryptocore.cli import main
from cryptocore.modes.cbc import encrypt as encrypt_cbc
from cryptocore.modes.cbc import encrypt_raw as encrypt_cbc_raw
from cryptocore.modes.cfb import encrypt as encrypt_cfb
from cryptocore.modes.ctr import encrypt as encrypt_ctr
from cryptocore.modes.ecb import encrypt as encrypt_ecb
from cryptocore.modes.ofb import encrypt as encrypt_ofb


KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
KEY = bytes.fromhex(KEY_HEX)
FIXED_IV = bytes(range(16))
MODE_ENCRYPTORS = {
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}


def cli_arguments(mode, operation, input_path, output_path, iv=None):
    arguments = [
        "--algorithm",
        "aes",
        "--mode",
        mode,
        operation,
        "--key",
        KEY_HEX,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
    ]
    if iv is not None:
        arguments.extend(["--iv", iv])
    return arguments


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_cli_encrypt_uses_generated_iv_and_writes_iv_before_ciphertext(
    mode, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    data = bytes([0x00, 0xFF, 0x10, 0x80]) * 9 + b"x"
    input_path.write_bytes(data)
    requested_sizes = []

    def fake_urandom(size):
        requested_sizes.append(size)
        return FIXED_IV

    monkeypatch.setattr("cryptocore.cli.os.urandom", fake_urandom)

    result = main(cli_arguments(mode, "--encrypt", input_path, output_path))

    output = output_path.read_bytes()
    captured = capsys.readouterr()
    assert result == 0
    assert requested_sizes == [16]
    assert output[:16] == FIXED_IV
    assert output[16:] == MODE_ENCRYPTORS[mode](KEY, FIXED_IV, data)
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.parametrize(
    ("mode", "expected_length"),
    [
        ("cbc", 32),
        ("cfb", 16),
        ("ofb", 16),
        ("ctr", 16),
    ],
)
def test_cli_encrypt_empty_file_has_expected_output_length(
    mode, expected_length, tmp_path, monkeypatch
):
    input_path = tmp_path / "empty.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(b"")
    monkeypatch.setattr("cryptocore.cli.os.urandom", lambda size: FIXED_IV)

    assert main(cli_arguments(mode, "--encrypt", input_path, output_path)) == 0

    output = output_path.read_bytes()
    assert output[:16] == FIXED_IV
    assert len(output) == expected_length


@pytest.mark.parametrize(
    ("mode", "expected_ciphertext_length"),
    [
        ("cbc", 32),
        ("cfb", 17),
        ("ofb", 17),
        ("ctr", 17),
    ],
)
def test_cli_encrypt_partial_file_has_expected_ciphertext_length(
    mode, expected_ciphertext_length, tmp_path, monkeypatch
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(b"x" * 17)
    monkeypatch.setattr("cryptocore.cli.os.urandom", lambda size: FIXED_IV)

    assert main(cli_arguments(mode, "--encrypt", input_path, output_path)) == 0

    output = output_path.read_bytes()
    assert output[:16] == FIXED_IV
    assert len(output[16:]) == expected_ciphertext_length


def test_cli_ecb_encrypt_does_not_request_iv(tmp_path, monkeypatch):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    data = b"ECB keeps the Sprint 1 file format"
    input_path.write_bytes(data)

    def reject_urandom_call(size):
        raise AssertionError(f"os.urandom must not be called for ECB: {size}")

    monkeypatch.setattr("cryptocore.cli.os.urandom", reject_urandom_call)

    assert main(cli_arguments("ecb", "--encrypt", input_path, output_path)) == 0
    assert output_path.read_bytes() == encrypt_ecb(KEY, data)
    assert not output_path.read_bytes().startswith(FIXED_IV)


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
@pytest.mark.parametrize(
    "data",
    [
        b"CryptoCore CLI round trip",
        bytes([0x00, 0xFF, 0x10, 0x80]) * 9 + b"x",
        b"",
    ],
)
def test_cli_new_mode_round_trip_uses_iv_from_file_header(
    mode, data, tmp_path, monkeypatch
):
    input_path = tmp_path / "input.bin"
    encrypted_path = tmp_path / "encrypted.bin"
    decrypted_path = tmp_path / "decrypted.bin"
    input_path.write_bytes(data)
    monkeypatch.setattr("cryptocore.cli.os.urandom", lambda size: FIXED_IV)

    encrypt_result = main(
        cli_arguments(mode, "--encrypt", input_path, encrypted_path)
    )
    decrypt_result = main(
        cli_arguments(mode, "--decrypt", encrypted_path, decrypted_path)
    )

    assert encrypt_result == 0
    assert decrypt_result == 0
    assert encrypted_path.read_bytes()[:16] == FIXED_IV
    assert decrypted_path.read_bytes() == data


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_cli_decrypt_with_explicit_iv_uses_entire_input_as_ciphertext(
    mode, tmp_path
):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    data = bytes([0x00, 0xFF, 0x10, 0x80]) * 13 + b"partial"
    ciphertext = MODE_ENCRYPTORS[mode](KEY, FIXED_IV, data)
    input_path.write_bytes(ciphertext)

    result = main(
        cli_arguments(
            mode,
            "--decrypt",
            input_path,
            output_path,
            iv=FIXED_IV.hex(),
        )
    )

    assert result == 0
    assert output_path.read_bytes() == data


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
@pytest.mark.parametrize("length", [0, 1, 15])
def test_cli_decrypt_without_iv_rejects_short_input_without_changing_output(
    mode, length, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    missing_output_path = tmp_path / "missing-output.bin"
    existing_output_path = tmp_path / "existing-output.bin"
    original_output = b"keep existing output"
    input_path.write_bytes(b"x" * length)
    existing_output_path.write_bytes(original_output)

    missing_result = main(
        cli_arguments(mode, "--decrypt", input_path, missing_output_path)
    )
    missing_error = capsys.readouterr()
    existing_result = main(
        cli_arguments(mode, "--decrypt", input_path, existing_output_path)
    )
    existing_error = capsys.readouterr()

    assert missing_result == 1
    assert existing_result == 1
    assert missing_error.out == ""
    assert existing_error.out == ""
    assert missing_error.err.startswith("error:")
    assert existing_error.err.startswith("error:")
    assert "IV" in missing_error.err
    assert str(input_path) in missing_error.err
    assert not missing_output_path.exists()
    assert existing_output_path.read_bytes() == original_output


def test_cli_cbc_decrypt_rejects_header_without_ciphertext(tmp_path, capsys):
    input_path = tmp_path / "encrypted.bin"
    output_path = tmp_path / "plaintext.bin"
    input_path.write_bytes(FIXED_IV)

    result = main(cli_arguments("cbc", "--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ciphertext length")
    assert not output_path.exists()


@pytest.mark.parametrize("mode", ["cfb", "ofb", "ctr"])
def test_cli_stream_mode_decrypt_accepts_header_without_ciphertext(
    mode, tmp_path
):
    input_path = tmp_path / "encrypted.bin"
    output_path = tmp_path / "plaintext.bin"
    input_path.write_bytes(FIXED_IV)

    result = main(cli_arguments(mode, "--decrypt", input_path, output_path))

    assert result == 0
    assert output_path.read_bytes() == b""


def test_cli_cbc_decrypt_rejects_empty_ciphertext_with_explicit_iv(
    tmp_path, capsys
):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    input_path.write_bytes(b"")

    result = main(
        cli_arguments(
            "cbc",
            "--decrypt",
            input_path,
            output_path,
            iv=FIXED_IV.hex(),
        )
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ciphertext length")
    assert not output_path.exists()


@pytest.mark.parametrize("mode", ["cfb", "ofb", "ctr"])
def test_cli_stream_mode_decrypt_accepts_empty_ciphertext_with_explicit_iv(
    mode, tmp_path
):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    input_path.write_bytes(b"")

    result = main(
        cli_arguments(
            mode,
            "--decrypt",
            input_path,
            output_path,
            iv=FIXED_IV.hex(),
        )
    )

    assert result == 0
    assert output_path.read_bytes() == b""


@pytest.mark.parametrize("ciphertext_length", [15, 17])
def test_cli_cbc_decrypt_rejects_invalid_ciphertext_length_without_overwrite(
    ciphertext_length, tmp_path, capsys
):
    input_path = tmp_path / "encrypted.bin"
    output_path = tmp_path / "plaintext.bin"
    original_output = b"keep existing output"
    input_path.write_bytes(FIXED_IV + b"x" * ciphertext_length)
    output_path.write_bytes(original_output)

    result = main(cli_arguments("cbc", "--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ciphertext length")
    assert output_path.read_bytes() == original_output


def test_cli_cbc_decrypt_reports_deterministic_invalid_padding(
    tmp_path, capsys
):
    input_path = tmp_path / "encrypted.bin"
    output_path = tmp_path / "plaintext.bin"
    original_output = b"keep existing output"
    ciphertext = encrypt_cbc_raw(KEY, FIXED_IV, b"\x00" * 16)
    input_path.write_bytes(FIXED_IV + ciphertext)
    output_path.write_bytes(original_output)

    result = main(cli_arguments("cbc", "--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "error: invalid padding (wrong key or corrupted data)\n"
    assert output_path.read_bytes() == original_output


@pytest.mark.parametrize(
    "iv",
    [
        "00" * 15,
        "00" * 17,
        "g0" + "00" * 15,
        "00" * 7 + " 0" + "00" * 8,
    ],
)
def test_cli_rejects_invalid_iv(iv, tmp_path, capsys):
    output_path = tmp_path / "output.bin"

    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                "cbc",
                "--decrypt",
                tmp_path / "input.bin",
                output_path,
                iv=iv,
            )
        )

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert not output_path.exists()


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_cli_rejects_iv_during_encryption(mode, tmp_path, monkeypatch, capsys):
    output_path = tmp_path / "output.bin"

    def reject_urandom_call(size):
        raise AssertionError(f"os.urandom must not be called: {size}")

    monkeypatch.setattr("cryptocore.cli.os.urandom", reject_urandom_call)

    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                mode,
                "--encrypt",
                tmp_path / "input.bin",
                output_path,
                iv=FIXED_IV.hex(),
            )
        )

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert not output_path.exists()


@pytest.mark.parametrize("operation", ["--encrypt", "--decrypt"])
def test_cli_rejects_iv_for_ecb(operation, tmp_path, capsys):
    output_path = tmp_path / "output.bin"

    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                "ecb",
                operation,
                tmp_path / "input.bin",
                output_path,
                iv=FIXED_IV.hex(),
            )
        )

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert not output_path.exists()


def test_cli_rejects_unknown_mode(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                "unknown", "--encrypt", tmp_path / "input.bin", tmp_path / "output.bin"
            )
        )

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
