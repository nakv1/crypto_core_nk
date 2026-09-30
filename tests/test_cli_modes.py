import pytest

from cryptocore.cli import main
from cryptocore.modes.cbc import encrypt as encrypt_cbc
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


def cli_arguments(mode, operation, input_path, output_path):
    return [
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
def test_cli_new_mode_decrypt_reports_temporary_error_without_output(
    mode, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(b"existing input")

    result = main(cli_arguments(mode, "--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "error: decryption for this mode is not implemented yet\n"
    assert not output_path.exists()


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_cli_new_mode_decrypt_does_not_overwrite_existing_output(
    mode, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    original_output = b"keep existing output"
    input_path.write_bytes(b"existing input")
    output_path.write_bytes(original_output)

    result = main(cli_arguments(mode, "--decrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err.startswith("error:")
    assert output_path.read_bytes() == original_output


def test_cli_rejects_unknown_mode(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                "unknown", "--encrypt", tmp_path / "input.bin", tmp_path / "output.bin"
            )
        )

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
