"""Проверка GCM с бинарным AAD, превышающим лимит памяти процесса.

Эталонный GCM PyCryptodome используется только родительским процессом.
Рабочий процесс использует собственный GCM и файловый поток AAD.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from check_large_hmac import _windows_memory_limit

MIB = 1024 * 1024
KEY = bytes(range(16))
NONCE = bytes(range(12))
PLAINTEXT = b"Authenticated with AAD larger than process memory."


def worker(directory, memory_mib):
    limit = memory_mib * MIB
    if os.name == "nt":
        peak = _windows_memory_limit(limit)
        metric = "peak_committed_bytes"
    else:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        peak = lambda: resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        metric = "peak_resident_bytes"
    directory = Path(directory)
    size = (directory / "aad.bin").stat().st_size
    try:
        entire_aad = bytearray(size)
    except MemoryError:
        pass
    else:
        del entire_aad
        raise RuntimeError("limit did not prevent allocating the entire AAD")

    from cryptocore.aead.files import decrypt_file
    from cryptocore.file_io import iter_chunks

    started = time.perf_counter()
    with (directory / "aad.bin").open("rb") as aad:
        decrypt_file(KEY, directory / "cipher.bin", directory / "result.bin", iter_chunks(aad))
    if (directory / "result.bin").read_bytes() != PLAINTEXT:
        raise RuntimeError("decrypted data does not match the reference")
    print(json.dumps({
        "size_bytes": size, "limit_bytes": limit, metric: peak(),
        "seconds": time.perf_counter() - started, "matched": True,
        "whole_aad_allocation_failed": True,
    }), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=65)
    parser.add_argument("--memory-mib", type=int, default=64)
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.memory_mib <= 0 or args.size_mib <= args.memory_mib:
        parser.error("AAD size must exceed a positive memory limit")
    if args.worker:
        worker(args.worker, args.memory_mib)
        return 0

    from Crypto.Cipher import AES

    with tempfile.TemporaryDirectory(prefix="cryptocore_aad_memory_") as directory:
        if shutil.disk_usage(directory).free < (args.size_mib + 64) * MIB:
            raise RuntimeError("not enough free disk space")
        directory = Path(directory)
        block = bytes(range(256)) * (MIB // 256)
        reference = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
        with (directory / "aad.bin").open("xb") as aad:
            for _ in range(args.size_mib):
                aad.write(block)
                reference.update(block)
        ciphertext, tag = reference.encrypt_and_digest(PLAINTEXT)
        (directory / "cipher.bin").write_bytes(NONCE + ciphertext + tag)
        env = os.environ.copy()
        source = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
        command = [sys.executable, str(Path(__file__).resolve()), "--worker", str(directory),
                   "--size-mib", str(args.size_mib), "--memory-mib", str(args.memory_mib)]
        result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
        if result.returncode:
            raise RuntimeError("limited-memory GCM failed: " + result.stderr)
        print(json.dumps(json.loads(result.stdout)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
