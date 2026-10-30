import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from cryptocore.cli import main


HASH_PATTERN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")

DATA_CASES = [
    pytest.param(b"", id="empty"),
    pytest.param(b"CryptoCore hash compatibility", id="text"),
    pytest.param(bytes(range(256)), id="all_bytes"),
    pytest.param(
        bytes((index * 17 + 3) % 256 for index in range(4097)),
        id="unaligned_4097",
    ),
]


def _run_process(command, cwd=None):
    """Запуск внешней утилиты с диагностическим выводом."""
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as error:
        pytest.fail(f"cannot run external command {command!r}: {error}")


def _check_sha256sum(executable: Path) -> str:
    """Проверка запуска найденного sha256sum."""
    resolved = executable.resolve()
    result = _run_process([str(resolved), "--version"])
    if result.returncode != 0:
        pytest.fail(
            f"sha256sum --version failed with code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return str(resolved)


def _find_sha256sum() -> str:
    """Поиск sha256sum в установленном порядке."""
    if "CRYPTOCORE_SHA256SUM" in os.environ:
        override = Path(os.environ["CRYPTOCORE_SHA256SUM"])
        if not override.is_file():
            pytest.fail(f"CRYPTOCORE_SHA256SUM file does not exist: {override}")
        return _check_sha256sum(override)

    path_result = shutil.which("sha256sum")
    if path_result is not None:
        return _check_sha256sum(Path(path_result))

    git_for_windows = Path(r"C:\Program Files\Git\usr\bin\sha256sum.exe")
    if git_for_windows.is_file():
        return _check_sha256sum(git_for_windows)

    pytest.skip("sha256sum executable not found")


def _check_openssl(executable: Path) -> str:
    """Проверка запуска найденного OpenSSL."""
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


def _find_sha3sum() -> str | None:
    """Поиск sha3sum без подмены несовместимой программы."""
    if "CRYPTOCORE_SHA3SUM" in os.environ:
        override = Path(os.environ["CRYPTOCORE_SHA3SUM"])
        if not override.is_file():
            pytest.fail(f"CRYPTOCORE_SHA3SUM file does not exist: {override}")
        return str(override.resolve())

    path_result = shutil.which("sha3sum")
    if path_result is not None:
        return str(Path(path_result).resolve())
    return None


@pytest.fixture(scope="module", params=["sha256", "sha3-256"])
def hash_reference(request):
    """Выбор внешнего эталона для алгоритма."""
    if request.param == "sha256":
        return request.param, "sha256sum", _find_sha256sum()

    sha3sum = _find_sha3sum()
    if sha3sum is not None:
        return request.param, "sha3sum", sha3sum
    return request.param, "openssl", _find_openssl()


def _external_command(kind, executable, file_name):
    """Формирование команды выбранной внешней утилиты."""
    if kind == "sha256sum":
        return [executable, file_name]
    if kind == "sha3sum":
        return [executable, "-a", "256", file_name]
    return [executable, "dgst", "-sha3-256", file_name]


def _extract_single_hash(stdout, stderr, source):
    """Извлечение единственного отдельного 64-символьного хеша."""
    matches = HASH_PATTERN.findall(stdout)
    if len(matches) != 1:
        pytest.fail(
            f"expected exactly one hash from {source}, found {len(matches)}\n"
            f"stdout: {stdout!r}\n"
            f"stderr: {stderr!r}"
        )
    return matches[0].lower()


@pytest.mark.parametrize("data", DATA_CASES)
def test_cryptocore_hash_matches_external_utility(
    hash_reference, data, tmp_path, monkeypatch, capsys
):
    algorithm, utility, executable = hash_reference
    file_name = "data.bin"
    (tmp_path / file_name).write_bytes(data)
    monkeypatch.chdir(tmp_path)

    cryptocore_result = main(
        ["dgst", "--algorithm", algorithm, "--input", file_name]
    )
    captured = capsys.readouterr()

    assert cryptocore_result == 0
    assert captured.err == ""
    cryptocore_hash = _extract_single_hash(
        captured.out, captured.err, "CryptoCore"
    )

    command = _external_command(utility, executable, file_name)
    external_result = _run_process(command, cwd=tmp_path)
    if external_result.returncode != 0:
        pytest.fail(
            f"external command failed with code {external_result.returncode}: "
            f"{command!r}\nstdout: {external_result.stdout!r}\n"
            f"stderr: {external_result.stderr!r}"
        )
    external_hash = _extract_single_hash(
        external_result.stdout,
        external_result.stderr,
        utility,
    )

    assert cryptocore_hash == external_hash
