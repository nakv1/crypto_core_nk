"""Проверяет HMAC файла, который нельзя целиком разместить в памяти процесса.

Запуск: python scripts/check_large_hmac.py --size-mib 1025 --memory-mib 512
Эталон hmac/hashlib используется только проверяющим родительским процессом.
"""

import argparse
import ctypes
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MIB = 1024 * 1024
KEY = bytes(range(32))
_JOB_HANDLE = None


def _windows_memory_limit(limit):
    """Ограничивает committed memory текущего процесса через Job Object."""
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD), ("min_ws", ctypes.c_size_t),
            ("max_ws", ctypes.c_size_t), ("active", wintypes.DWORD),
            ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
            ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
            ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.basic.flags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    limits.process_memory = limit
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        raise ctypes.WinError(ctypes.get_last_error())
    global _JOB_HANDLE
    _JOB_HANDLE = handle  # Job должен существовать до завершения рабочего процесса.

    def peak_memory():
        result = ExtendedLimits()
        if not kernel.QueryInformationJobObject(handle, 9, ctypes.byref(result), ctypes.sizeof(result), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return result.peak_process

    return peak_memory


def _worker(path, memory_mib):
    limit = memory_mib * MIB
    if os.name == "nt":
        peak_memory = _windows_memory_limit(limit)
        metric = "peak_committed_bytes"
    else:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        # LLVM может резервировать адресное пространство сверх RLIMIT_AS.
        # Обычный Python позволяет проверить этот лимит без зависимости от LLVM.
        os.environ["CRYPTOCORE_PURE_PYTHON"] = "1"
        peak_memory = lambda: resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        metric = "peak_resident_bytes"
    size = Path(path).stat().st_size
    try:
        whole_file = bytearray(size)
    except MemoryError:
        pass
    else:
        del whole_file
        raise RuntimeError("memory limit did not prevent allocating the entire file")

    from cryptocore.file_io import iter_chunks
    from cryptocore.mac import HMAC

    started = time.perf_counter()
    mac = HMAC(KEY)
    with Path(path).open("rb") as source:
        for chunk in iter_chunks(source):
            mac.update(chunk)
    print(json.dumps({
        "size_bytes": size, "limit_bytes": limit, metric: peak_memory(),
        "seconds": time.perf_counter() - started, "hmac": mac.hexdigest(),
        "whole_file_allocation_failed": True,
    }), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=1025)
    parser.add_argument("--memory-mib", type=int, default=512)
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.memory_mib <= 0 or args.size_mib <= args.memory_mib:
        parser.error("size must exceed a positive memory limit")
    if args.worker:
        _worker(args.worker, args.memory_mib)
        return 0

    with tempfile.TemporaryDirectory(prefix="cryptocore_hmac_memory_") as directory:
        if shutil.disk_usage(directory).free < (args.size_mib + 256) * MIB:
            raise RuntimeError("not enough free disk space")
        path = Path(directory) / "large.bin"
        block = bytes(range(256)) * (MIB // 256)
        reference = hmac.new(KEY, digestmod="sha256")
        with path.open("xb") as output:
            for _ in range(args.size_mib):
                output.write(block)
                reference.update(block)
        env = os.environ.copy()
        src = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        command = [sys.executable, str(Path(__file__).resolve()), "--worker", str(path),
                   "--size-mib", str(args.size_mib), "--memory-mib", str(args.memory_mib)]
        result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
        if result.returncode:
            raise RuntimeError(f"limited-memory worker failed: {result.stderr}")
        report = json.loads(result.stdout)
        if report["hmac"] != reference.hexdigest():
            raise RuntimeError("HMAC does not match the reference")
        report["matched"] = True
        print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
