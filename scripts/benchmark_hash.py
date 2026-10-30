"""Замеряет скорость хеширования CryptoCore и системных утилит."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path


DEFAULT_SIZES = [1, 10]
CHUNK_SIZE = 64 * 1024
HASH_PATTERN = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"
)
DATA_BLOCK = bytes(range(256)) * (CHUNK_SIZE // 256)


def _positive_size(value: str) -> int:
    """Преобразует положительный размер в МиБ."""
    try:
        size = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("size must be a positive integer") from exc
    if size <= 0:
        raise argparse.ArgumentTypeError("size must be a positive integer")
    return size


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Запускает внешнюю команду для проверки утилиты."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        raise RuntimeError(f"failed to run {command[0]}: {exc}") from exc


def _find_sha256sum() -> str:
    """Находит и проверяет sha256sum."""
    if "CRYPTOCORE_SHA256SUM" in os.environ:
        override = Path(os.environ["CRYPTOCORE_SHA256SUM"])
        if not override.is_file():
            raise RuntimeError(f"sha256sum not found: {override}")
        candidates = [override]
    else:
        candidates = []
    path_candidate = shutil.which("sha256sum")
    if not candidates and path_candidate:
        candidates.append(path_candidate)
    if not candidates:
        candidates.append(r"C:\Program Files\Git\usr\bin\sha256sum.exe")

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            result = _run([candidate, "--version"])
            if result.returncode != 0:
                raise RuntimeError(
                    f"sha256sum check failed: {result.stderr.strip()}"
                )
            return str(Path(candidate).resolve())
    raise RuntimeError("sha256sum not found")


def _find_sha3sum() -> str | None:
    """Находит sha3sum, если он доступен."""
    override = os.environ.get("CRYPTOCORE_SHA3SUM")
    if override:
        if not Path(override).is_file():
            raise RuntimeError(f"sha3sum not found: {override}")
        return str(Path(override).resolve())

    candidate = shutil.which("sha3sum")
    if candidate:
        return str(Path(candidate).resolve())
    return None


def _find_openssl() -> str:
    """Находит и проверяет OpenSSL."""
    if "CRYPTOCORE_OPENSSL" in os.environ:
        override = Path(os.environ["CRYPTOCORE_OPENSSL"])
        if not override.is_file():
            raise RuntimeError(f"OpenSSL not found: {override}")
        candidates = [override]
    else:
        candidates = []
    path_candidate = shutil.which("openssl")
    if not candidates and path_candidate:
        candidates.append(path_candidate)
    if not candidates:
        candidates.append(r"C:\Program Files\Git\usr\bin\openssl.exe")

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            result = _run([candidate, "version"])
            version = (result.stdout or result.stderr).strip()
            if result.returncode != 0 or "OpenSSL" not in version:
                details = result.stderr.strip() or result.stdout.strip()
                raise RuntimeError(f"OpenSSL check failed: {details}")
            return str(Path(candidate).resolve())
    raise RuntimeError("OpenSSL not found")


def _write_data(path: Path, size: int) -> None:
    """Создаёт детерминированный файл заданного размера."""
    remaining = size
    with path.open("xb") as output_file:
        while remaining > 0:
            current_size = min(remaining, CHUNK_SIZE)
            output_file.write(DATA_BLOCK[:current_size])
            remaining -= current_size


def _measure(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], float]:
    """Запускает команду и возвращает результат с временем работы."""
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        raise RuntimeError(f"failed to run {command[0]}: {exc}") from exc
    elapsed = time.perf_counter() - started
    return result, elapsed


def _check_result(
    result: subprocess.CompletedProcess[str], label: str
) -> str:
    """Проверяет код возврата и извлекает единственный хеш."""
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{label} failed: {details}")

    matches = HASH_PATTERN.findall(result.stdout)
    if len(matches) != 1:
        raise RuntimeError(
            f"{label} returned {len(matches)} hashes; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return matches[0].lower()


def _crypto_env(project_root: Path) -> dict[str, str]:
    """Готовит окружение для запуска CryptoCore из исходников."""
    env = os.environ.copy()
    src_path = str(project_root / "src")
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_path if not current else src_path + os.pathsep + current
    )
    return env


def main(argv: Sequence[str] | None = None) -> int:
    """Разбирает аргументы и выполняет замеры."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=_positive_size,
        default=DEFAULT_SIZES,
        metavar="MIB",
        help="file sizes in MiB (default: 1 10)",
    )
    args = parser.parse_args(argv)

    try:
        sha256sum = _find_sha256sum()
        sha3sum = _find_sha3sum()
        openssl = None if sha3sum else _find_openssl()

        print(f"SHA-256 reference: {sha256sum}", flush=True)
        if sha3sum:
            print(f"SHA3-256 reference: {sha3sum} (-a 256)", flush=True)
        else:
            print(
                f"SHA3-256 reference: {openssl} (dgst -sha3-256)",
                flush=True,
            )
        print(
            "algorithm | size MiB | CryptoCore s | CryptoCore MiB/s | "
            "reference | reference s | reference MiB/s | hash matched",
            flush=True,
        )

        project_root = Path(__file__).resolve().parents[1]
        crypto_env = _crypto_env(project_root)

        with tempfile.TemporaryDirectory(prefix="cryptocore_benchmark_") as temp:
            temp_path = Path(temp)
            for size_mib in args.sizes:
                data_path = temp_path / f"data_{size_mib}_mib.bin"
                _write_data(data_path, size_mib * 1024 * 1024)
                input_path = str(data_path.resolve())

                for algorithm in ("sha256", "sha3-256"):
                    crypto_command = [
                        sys.executable,
                        "-m",
                        "cryptocore",
                        "dgst",
                        "--algorithm",
                        algorithm,
                        "--input",
                        input_path,
                    ]
                    if algorithm == "sha256":
                        reference_name = "sha256sum"
                        reference_command = [sha256sum, input_path]
                    elif sha3sum:
                        reference_name = "sha3sum"
                        reference_command = [sha3sum, "-a", "256", input_path]
                    else:
                        reference_name = "openssl"
                        reference_command = [
                            openssl,
                            "dgst",
                            "-sha3-256",
                            input_path,
                        ]

                    crypto_result, crypto_time = _measure(
                        crypto_command,
                        cwd=project_root,
                        env=crypto_env,
                    )
                    reference_result, reference_time = _measure(
                        reference_command,
                        cwd=project_root,
                    )
                    crypto_hash = _check_result(crypto_result, "CryptoCore")
                    reference_hash = _check_result(
                        reference_result, reference_name
                    )
                    if crypto_hash != reference_hash:
                        raise RuntimeError(
                            f"hash mismatch for {algorithm}, {size_mib} MiB"
                        )

                    crypto_speed = size_mib / crypto_time
                    reference_speed = size_mib / reference_time
                    print(
                        f"{algorithm} | {size_mib} | {crypto_time:.6f} | "
                        f"{crypto_speed:.3f} | {reference_name} | "
                        f"{reference_time:.6f} | {reference_speed:.3f} | yes",
                        flush=True,
                    )
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
