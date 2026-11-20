"""Одинаковые ответы при исполнении раундов Python и JIT."""

import hashlib
from importlib.util import find_spec

import pytest

from cryptocore.hash import SHA256


@pytest.mark.parametrize("pure", [True, False], ids=["python", "jit"])
@pytest.mark.parametrize("length", [8192, 8193, 20000])
def test_sha256_backends(pure, length, monkeypatch):
    if not pure and find_spec("numba") is None:
        pytest.skip("install cryptocore[speed] to test JIT")
    monkeypatch.setenv("CRYPTOCORE_PURE_PYTHON", "1" if pure else "0")
    data = bytes((i * 37 + 11) % 256 for i in range(length))
    actual = SHA256()
    actual.update(b"prefix")
    actual.update(data)
    actual.update(b"suffix")
    assert actual.hexdigest() == hashlib.sha256(b"prefix" + data + b"suffix").hexdigest()
    assert len(actual._buffer) < actual.block_size
