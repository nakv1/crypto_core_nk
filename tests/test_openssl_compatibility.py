import os
from pathlib import Path
import shutil
import subprocess

import pytest

from cryptocore.cli import main
from cryptocore.modes.cbc import encrypt as encrypt_cbc
from cryptocore.modes.cfb import encrypt as encrypt_cfb
from cryptocore.modes.ctr import encrypt as encrypt_ctr
from cryptocore.modes.ofb import encrypt as encrypt_ofb


KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
IV_HEX = "101112131415161718191a1b1c1d1e1f"
IV = bytes.fromhex(IV_HEX)
PLAINTEXT = bytes([0x00, 0xFF]) + bytes(range(45))

OPENSSL_CIPHERS = {
    "cbc": "aes-128-cbc",
    "cfb": "aes-128-cfb",
    "ofb": "aes-128-ofb",
    "ctr": "aes-128-ctr",
}
MODE_ENCRYPTORS = {
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}


def _run_process(command):
    """Запуск OpenSSL с сохранением диагностического вывода."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as error:
        pytest.fail(f"cannot run OpenSSL command {command!r}: {error}")


def _check_openssl(executable: Path) -> str:
    """Проверка, что найденный файл запускается как OpenSSL."""
    resolved = executable.resolve()
    result = _run_process([str(resolved), "version"])
    version = (result.stdout or result.stderr).strip()
    if result.returncode != 0:
        pytest.fail(
            f"OpenSSL version command failed with code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    if "OpenSSL" not in version:
        pytest.fail(f"executable does not report an OpenSSL version: {version!r}")
    return str(resolved)


def _find_openssl() -> str:
    """Поиск OpenSSL в установленном порядке."""
    if "CRYPTOCORE_OPENSSL" in os.environ:
        override = Path(os.environ["CRYPTOCORE_OPENSSL"])
        if not override.is_file():
            pytest.fail(f"CRYPTOCORE_OPENSSL file does not exist: {override}")
        return _check_openssl(override)

    path_result = shutil.which("openssl")
    if path_result is not None:
        return _check_openssl(Path(path_result))

    git_for_windows = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if git_for_windows.is_file():
        return _check_openssl(git_for_windows)

    pytest.skip("OpenSSL executable not found")


def _assert_openssl_succeeded(result, command):
    """Проверка успешного завершения команды OpenSSL."""
    assert result.returncode == 0, (
        f"OpenSSL command failed with code {result.returncode}: {command!r}\n"
        f"stderr: {result.stderr.strip()}"
    )


def _cli_arguments(mode, operation, input_path, output_path, iv=None):
    """Формирование аргументов CryptoCore для тестов совместимости."""
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


@pytest.fixture(scope="module")
def openssl_path():
    """Путь к проверенному исполняемому файлу OpenSSL."""
    return _find_openssl()


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_cryptocore_encrypt_openssl_decrypt(
    mode, openssl_path, tmp_path, monkeypatch
):
    plaintext_path = tmp_path / "plaintext.bin"
    cryptocore_cipher_path = tmp_path / "cryptocore-cipher.bin"
    raw_ciphertext_path = tmp_path / "ciphertext.raw"
    openssl_plaintext_path = tmp_path / "openssl-plaintext.bin"
    plaintext_path.write_bytes(PLAINTEXT)
    monkeypatch.setattr("cryptocore.cli.os.urandom", lambda size: IV)

    cryptocore_result = main(
        _cli_arguments(
            mode,
            "--encrypt",
            plaintext_path,
            cryptocore_cipher_path,
        )
    )

    assert cryptocore_result == 0
    encrypted = cryptocore_cipher_path.read_bytes()
    assert len(encrypted) >= 16
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    assert iv == IV
    raw_ciphertext_path.write_bytes(ciphertext)

    command = [
        openssl_path,
        "enc",
        f"-{OPENSSL_CIPHERS[mode]}",
        "-d",
        "-K",
        KEY_HEX,
        "-iv",
        iv.hex(),
        "-in",
        str(raw_ciphertext_path),
        "-out",
        str(openssl_plaintext_path),
    ]
    openssl_result = _run_process(command)

    _assert_openssl_succeeded(openssl_result, command)
    assert openssl_plaintext_path.read_bytes() == PLAINTEXT


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_openssl_encrypt_cryptocore_decrypt(mode, openssl_path, tmp_path):
    plaintext_path = tmp_path / "plaintext.bin"
    openssl_ciphertext_path = tmp_path / "openssl-ciphertext.bin"
    cryptocore_plaintext_path = tmp_path / "cryptocore-plaintext.bin"
    plaintext_path.write_bytes(PLAINTEXT)

    command = [
        openssl_path,
        "enc",
        f"-{OPENSSL_CIPHERS[mode]}",
        "-K",
        KEY_HEX,
        "-iv",
        IV_HEX,
        "-in",
        str(plaintext_path),
        "-out",
        str(openssl_ciphertext_path),
    ]
    openssl_result = _run_process(command)
    _assert_openssl_succeeded(openssl_result, command)

    cryptocore_result = main(
        _cli_arguments(
            mode,
            "--decrypt",
            openssl_ciphertext_path,
            cryptocore_plaintext_path,
            iv=IV_HEX,
        )
    )

    assert cryptocore_result == 0
    assert cryptocore_plaintext_path.read_bytes() == PLAINTEXT
    assert openssl_ciphertext_path.read_bytes() == MODE_ENCRYPTORS[mode](
        KEY, IV, PLAINTEXT
    )
