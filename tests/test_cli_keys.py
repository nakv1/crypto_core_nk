import re
from unittest.mock import Mock, call

import pytest

from cryptocore.cli import main
from cryptocore.csprng import RandomGenerationError
from cryptocore.modes.cbc import encrypt as encrypt_cbc
from cryptocore.modes.cfb import encrypt as encrypt_cfb
from cryptocore.modes.ctr import encrypt as encrypt_ctr
from cryptocore.modes.ecb import encrypt as encrypt_ecb
from cryptocore.modes.ofb import encrypt as encrypt_ofb


MODES_WITH_IV = ["cbc", "cfb", "ofb", "ctr"]
ALL_MODES = ["ecb", *MODES_WITH_IV]
MODE_ENCRYPTORS = {
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}
FIXED_IV = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
GENERATED_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
SAFE_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
PREDICTABLE_KEY = bytes(range(16))
GENERATED_KEY_LINE = f"[INFO] Generated random key: {GENERATED_KEY.hex()}\n"


def cli_arguments(mode, operation, input_path, output_path=None, key=None, iv=None):
    arguments = [
        "--algorithm",
        "aes",
        "--mode",
        mode,
        operation,
        "--input",
        str(input_path),
    ]
    if key is not None:
        key_hex = key.hex() if isinstance(key, bytes) else key
        arguments.extend(["--key", key_hex])
    if output_path is not None:
        arguments.extend(["--output", str(output_path)])
    if iv is not None:
        arguments.extend(["--iv", iv])
    return arguments


def set_generator(monkeypatch, side_effect):
    generator = Mock(side_effect=side_effect)
    monkeypatch.setattr(
        "cryptocore.cli.csprng.generate_random_bytes", generator
    )
    return generator


@pytest.mark.parametrize("mode", MODES_WITH_IV)
def test_generated_key_encrypts_iv_mode_and_matches_explicit_key(
    mode, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    generated_output = tmp_path / "generated.bin"
    explicit_output = tmp_path / "explicit.bin"
    data = b"different deterministic IV and generated AES key"
    input_path.write_bytes(data)

    generated_mock = set_generator(monkeypatch, [FIXED_IV, GENERATED_KEY])
    generated_result = main(
        cli_arguments(mode, "--encrypt", input_path, generated_output)
    )
    generated_capture = capsys.readouterr()

    assert generated_result == 0
    assert generated_mock.call_args_list == [call(16), call(16)]
    assert generated_capture.out == GENERATED_KEY_LINE
    assert re.fullmatch(
        r"\[INFO\] Generated random key: [0-9a-f]{32}\n",
        generated_capture.out,
    )
    assert generated_capture.err == ""
    generated_data = generated_output.read_bytes()
    assert generated_data[:16] == FIXED_IV
    assert generated_data[16:] == MODE_ENCRYPTORS[mode](
        GENERATED_KEY, FIXED_IV, data
    )

    explicit_mock = set_generator(monkeypatch, [FIXED_IV])
    explicit_result = main(
        cli_arguments(
            mode,
            "--encrypt",
            input_path,
            explicit_output,
            key=GENERATED_KEY,
        )
    )
    explicit_capture = capsys.readouterr()

    assert explicit_result == 0
    assert explicit_mock.call_args_list == [call(16)]
    assert explicit_capture.out == ""
    assert explicit_capture.err == ""
    assert explicit_output.read_bytes() == generated_data


def test_generated_key_encrypts_ecb_and_matches_explicit_key(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    generated_output = tmp_path / "generated.bin"
    explicit_output = tmp_path / "explicit.bin"
    data = b"ECB generated key"
    input_path.write_bytes(data)

    generated_mock = set_generator(monkeypatch, [GENERATED_KEY])
    generated_result = main(
        cli_arguments("ecb", "--encrypt", input_path, generated_output)
    )
    generated_capture = capsys.readouterr()

    assert generated_result == 0
    assert generated_mock.call_args_list == [call(16)]
    assert generated_capture.out == GENERATED_KEY_LINE
    assert re.fullmatch(
        r"\[INFO\] Generated random key: [0-9a-f]{32}\n",
        generated_capture.out,
    )
    assert generated_capture.err == ""
    assert generated_output.read_bytes() == encrypt_ecb(GENERATED_KEY, data)

    explicit_mock = set_generator(monkeypatch, [])
    explicit_result = main(
        cli_arguments(
            "ecb",
            "--encrypt",
            input_path,
            explicit_output,
            key=GENERATED_KEY,
        )
    )
    explicit_capture = capsys.readouterr()

    assert explicit_result == 0
    assert explicit_mock.call_args_list == []
    assert explicit_capture.out == ""
    assert explicit_capture.err == ""
    assert explicit_output.read_bytes() == generated_output.read_bytes()


@pytest.mark.parametrize("mode", ALL_MODES)
def test_generated_key_round_trip(mode, tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "plaintext.bin"
    encrypted_path = tmp_path / "ciphertext.bin"
    decrypted_path = tmp_path / "decrypted.bin"
    data = b"round trip with a generated key"
    input_path.write_bytes(data)
    side_effect = [GENERATED_KEY] if mode == "ecb" else [FIXED_IV, GENERATED_KEY]

    encrypt_mock = set_generator(monkeypatch, side_effect)
    encrypt_result = main(
        cli_arguments(mode, "--encrypt", input_path, encrypted_path)
    )
    encrypt_capture = capsys.readouterr()
    match = re.fullmatch(
        r"\[INFO\] Generated random key: ([0-9a-f]{32})\n",
        encrypt_capture.out,
    )

    assert encrypt_result == 0
    assert match is not None
    assert match.group(1) == GENERATED_KEY.hex()
    assert encrypt_capture.err == ""
    expected_calls = [call(16)] if mode == "ecb" else [call(16), call(16)]
    assert encrypt_mock.call_args_list == expected_calls

    decrypt_mock = set_generator(monkeypatch, [])
    decrypt_result = main(
        cli_arguments(
            mode,
            "--decrypt",
            encrypted_path,
            decrypted_path,
            key=bytes.fromhex(match.group(1)),
        )
    )
    decrypt_capture = capsys.readouterr()

    assert decrypt_result == 0
    assert decrypt_mock.call_args_list == []
    assert decrypt_capture.out == ""
    assert decrypt_capture.err == ""
    assert decrypted_path.read_bytes() == data


def test_generated_key_is_not_printed_for_missing_input(
    tmp_path, monkeypatch, capsys
):
    generator = set_generator(monkeypatch, [])

    result = main(
        cli_arguments(
            "cbc",
            "--encrypt",
            tmp_path / "missing.bin",
            tmp_path / "output.bin",
        )
    )

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == []
    assert captured.out == ""
    assert "error:" in captured.err


def test_generated_key_is_not_printed_for_automatic_output_conflict(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "plaintext.bin.enc"
    original_output = b"existing automatic output"
    input_path.write_bytes(b"plaintext")
    output_path.write_bytes(original_output)
    generator = set_generator(monkeypatch, [])

    result = main(cli_arguments("cbc", "--encrypt", input_path))

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == []
    assert captured.out == ""
    assert "error:" in captured.err
    assert output_path.read_bytes() == original_output


@pytest.mark.parametrize("mode", MODES_WITH_IV)
def test_generated_key_is_not_printed_when_iv_generation_fails(
    mode, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "ciphertext.bin"
    input_path.write_bytes(b"plaintext")
    generator = set_generator(
        monkeypatch,
        [RandomGenerationError("failed to generate random bytes")],
    )

    result = main(cli_arguments(mode, "--encrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == [call(16)]
    assert captured.out == ""
    assert "error:" in captured.err
    assert not output_path.exists()


@pytest.mark.parametrize("mode", ALL_MODES)
@pytest.mark.parametrize("existing_output", [False, True])
def test_cli_reports_generated_key_failure_without_changing_output(
    mode, existing_output, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "ciphertext.bin"
    original_output = b"existing output"
    input_path.write_bytes(b"plaintext")
    if existing_output:
        output_path.write_bytes(original_output)
    generation_error = RandomGenerationError("failed to generate random bytes")
    side_effect = [generation_error] if mode == "ecb" else [FIXED_IV, generation_error]
    generator = set_generator(monkeypatch, side_effect)

    result = main(cli_arguments(mode, "--encrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    expected_calls = [call(16)] if mode == "ecb" else [call(16), call(16)]
    assert generator.call_args_list == expected_calls
    assert captured.out == ""
    assert "error:" in captured.err
    assert "Traceback" not in captured.err
    if existing_output:
        assert output_path.read_bytes() == original_output
    else:
        assert not output_path.exists()


def test_decrypt_without_key_fails_before_input_read_or_csprng(
    tmp_path, monkeypatch, capsys
):
    generator = set_generator(monkeypatch, [])

    with pytest.raises(SystemExit) as error:
        main(
            cli_arguments(
                "cbc",
                "--decrypt",
                tmp_path / "missing.bin",
                tmp_path / "output.bin",
            )
        )

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert generator.call_args_list == []
    assert captured.out == ""
    assert "--key" in captured.err


@pytest.mark.parametrize(
    "key_hex",
    [
        "00" * 16,
        "ff" * 16,
        "41" * 16,
        "000102030405060708090a0b0c0d0e0f",
        "0f0e0d0c0b0a09080706050403020100",
    ],
)
def test_cli_warns_once_for_predictable_user_key(
    key_hex, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "ciphertext.bin"
    input_path.write_bytes(b"plaintext")
    generator = set_generator(monkeypatch, [])

    result = main(
        cli_arguments("ecb", "--encrypt", input_path, output_path, key=key_hex)
    )

    captured = capsys.readouterr()
    assert result == 0
    assert generator.call_args_list == []
    assert captured.out == ""
    assert captured.err == "warning: key looks predictable\n"


@pytest.mark.parametrize(
    "key_hex",
    [
        SAFE_KEY.hex(),
        "f8f9fafbfcfdfeff0001020304050607",
        "0706050403020100fffefdfcfbfaf9f8",
    ],
)
def test_cli_does_not_warn_for_non_predictable_user_key(
    key_hex, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "ciphertext.bin"
    input_path.write_bytes(b"plaintext")
    generator = set_generator(monkeypatch, [])

    result = main(
        cli_arguments("ecb", "--encrypt", input_path, output_path, key=key_hex)
    )

    captured = capsys.readouterr()
    assert result == 0
    assert generator.call_args_list == []
    assert captured.out == ""
    assert captured.err == ""


def test_cli_warns_for_predictable_key_during_decrypt(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "ciphertext.bin"
    output_path = tmp_path / "plaintext.bin"
    data = b"decrypt predictable key warning"
    input_path.write_bytes(encrypt_ecb(PREDICTABLE_KEY, data))
    generator = set_generator(monkeypatch, [])

    result = main(
        cli_arguments(
            "ecb",
            "--decrypt",
            input_path,
            output_path,
            key=PREDICTABLE_KEY,
        )
    )

    captured = capsys.readouterr()
    assert result == 0
    assert generator.call_args_list == []
    assert captured.out == ""
    assert captured.err == "warning: key looks predictable\n"
    assert output_path.read_bytes() == data


def test_generated_predictable_key_does_not_produce_warning(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "ciphertext.bin"
    input_path.write_bytes(b"plaintext")
    generator = set_generator(monkeypatch, [PREDICTABLE_KEY])

    result = main(cli_arguments("ecb", "--encrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 0
    assert generator.call_args_list == [call(16)]
    assert captured.out == (
        f"[INFO] Generated random key: {PREDICTABLE_KEY.hex()}\n"
    )
    assert captured.err == ""


def test_generated_key_remains_printed_when_output_write_fails(
    tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "plaintext.bin"
    output_path = tmp_path / "missing" / "ciphertext.bin"
    input_path.write_bytes(b"plaintext")
    generator = set_generator(monkeypatch, [GENERATED_KEY])

    result = main(cli_arguments("ecb", "--encrypt", input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == [call(16)]
    assert captured.out == GENERATED_KEY_LINE
    assert "error:" in captured.err
    assert not output_path.exists()
