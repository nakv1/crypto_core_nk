"""Воспроизводимые замеры собственного PBKDF2-HMAC-SHA256.

Пароль и salt фиксированы и публичны; это тестовые данные. hashlib
используется исключительно как эталон. Прогрев измеряется отдельно.
"""

import argparse
import hashlib
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import platform
import sys
import time

from cryptocore.kdf import pbkdf2_hmac_sha256

PASSWORD = b"benchmark-password"
SALT = bytes(range(16))


def positive(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", nargs="+", type=positive, default=[10000, 100000, 1000000])
    parser.add_argument("--length", type=positive, default=32)
    parser.add_argument("--pure-python", action="store_true")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    if args.pure_python:
        os.environ["CRYPTOCORE_PURE_PYTHON"] = "1"
    try:
        numba_version = version("numba")
    except PackageNotFoundError:
        numba_version = None
    kdf_module = import_module("cryptocore.kdf.pbkdf2")
    started = time.perf_counter()
    warmup = pbkdf2_hmac_sha256(PASSWORD, SALT, 1000, args.length)
    warmup_seconds = time.perf_counter() - started
    if warmup != hashlib.pbkdf2_hmac("sha256", PASSWORD, SALT, 1000, args.length):
        raise RuntimeError("warmup result differs from the reference")
    report = {
        "python": sys.version, "platform": platform.platform(), "numba": numba_version,
        "password_hex": PASSWORD.hex(), "salt_hex": SALT.hex(), "length": args.length,
        "warmup_iterations": 1000, "warmup_seconds": warmup_seconds, "results": [],
    }
    print(json.dumps({key: value for key, value in report.items() if key != "results"}), flush=True)
    for iterations in args.iterations:
        backend = "jit" if kdf_module._get_chain(iterations) is not None else "python"
        started = time.perf_counter()
        actual = pbkdf2_hmac_sha256(PASSWORD, SALT, iterations, args.length)
        elapsed = time.perf_counter() - started
        reference_started = time.perf_counter()
        expected = hashlib.pbkdf2_hmac("sha256", PASSWORD, SALT, iterations, args.length)
        reference_seconds = time.perf_counter() - reference_started
        if actual != expected:
            raise RuntimeError(f"PBKDF2 differs from reference at {iterations} iterations")
        row = {"iterations": iterations, "backend": backend, "seconds": elapsed,
               "reference_seconds": reference_seconds, "key_hex": actual.hex(), "matched": True}
        report["results"].append(row)
        print(json.dumps(row), flush=True)
    if args.json_output is not None:
        args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
