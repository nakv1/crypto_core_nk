import hashlib
import os
import shutil
import time

import pytest

from cryptocore.cli import main


MIB = 1024 * 1024
DEFAULT_SIZE_MIB = 1025
FREE_SPACE_MARGIN = 256 * MIB
DATA_BLOCK = bytes(range(256)) * (MIB // 256)

pytestmark = pytest.mark.skipif(
    os.environ.get("CRYPTOCORE_RUN_LARGE_TESTS") != "1",
    reason="set CRYPTOCORE_RUN_LARGE_TESTS=1 to run large-file tests",
)


def _large_size_mib() -> int:
    """Возвращает размер тестового файла в МиБ."""
    value = os.environ.get("CRYPTOCORE_LARGE_TEST_MIB")
    if value is None:
        return DEFAULT_SIZE_MIB

    try:
        size_mib = int(value)
    except ValueError:
        pytest.fail("CRYPTOCORE_LARGE_TEST_MIB must be a positive integer")
    if size_mib <= 0:
        pytest.fail("CRYPTOCORE_LARGE_TEST_MIB must be a positive integer")
    return size_mib


@pytest.fixture(scope="module")
def large_file(tmp_path_factory):
    """Создаёт общий файл и эталонные хеши для двух алгоритмов."""
    size_mib = _large_size_mib()
    size_bytes = size_mib * MIB
    directory = tmp_path_factory.mktemp("large_file_hash")
    file_path = directory / "large_data.bin"
    free_space = shutil.disk_usage(directory).free
    required_space = size_bytes + FREE_SPACE_MARGIN

    if free_space < required_space:
        pytest.fail(
            f"not enough free space: need {required_space} bytes, "
            f"available {free_space} bytes"
        )

    references = {
        "sha256": hashlib.sha256(),
        "sha3-256": hashlib.sha3_256(),
    }

    try:
        remaining = size_bytes
        with file_path.open("xb") as output_file:
            while remaining > 0:
                current_size = min(remaining, MIB)
                data = DATA_BLOCK[:current_size]
                output_file.write(data)
                for reference in references.values():
                    reference.update(data)
                remaining -= current_size

        expected = {
            algorithm: reference.hexdigest()
            for algorithm, reference in references.items()
        }
        yield file_path, size_mib, expected
    finally:
        try:
            file_path.unlink()
        except FileNotFoundError:
            pass


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_hashes_file_larger_than_one_gibibyte(
    algorithm, large_file, monkeypatch, capsys
):
    file_path, size_mib, expected = large_file
    monkeypatch.chdir(file_path.parent)

    started = time.perf_counter()
    result = main(
        [
            "dgst",
            "--algorithm",
            algorithm,
            "--input",
            file_path.name,
        ]
    )
    elapsed = time.perf_counter() - started

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out == f"{expected[algorithm]}  {file_path.name}\n"

    speed = size_mib / elapsed
    with capsys.disabled():
        print(
            f"{algorithm}: {size_mib} MiB, {elapsed:.3f} s, "
            f"{speed:.3f} MiB/s",
            flush=True,
        )
