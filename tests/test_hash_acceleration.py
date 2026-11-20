"""Одинаковые ответы при исполнении раундов Python и JIT."""

import hashlib
from importlib import import_module
from importlib.util import find_spec

import pytest

from cryptocore.hash import SHA256, SHA3_256


@pytest.mark.parametrize("pure", [True, False], ids=["python", "jit"])
@pytest.mark.parametrize("length", [8192, 8193, 20000])
@pytest.mark.parametrize(("implementation", "reference"), [
    (SHA256, hashlib.sha256), (SHA3_256, hashlib.sha3_256),
])
def test_hash_backends(pure, length, implementation, reference, monkeypatch):
    if not pure and find_spec("numba") is None:
        pytest.skip("install cryptocore[speed] to test JIT")
    monkeypatch.setenv("CRYPTOCORE_PURE_PYTHON", "1" if pure else "0")
    data = bytes((i * 37 + 11) % 256 for i in range(length))
    actual = implementation()
    actual.update(b"prefix")
    actual.update(data)
    actual.update(b"suffix")
    assert actual.hexdigest() == reference(b"prefix" + data + b"suffix").hexdigest()
    assert len(actual._buffer) < actual.block_size


@pytest.mark.parametrize("algorithm", ["sha256", "sha3"])
def test_missing_compiler_uses_python(algorithm, monkeypatch):
    from cryptocore.hash import acceleration

    monkeypatch.delenv("CRYPTOCORE_PURE_PYTHON", raising=False)
    monkeypatch.setattr(acceleration, "find_spec", lambda name: None)
    acceleration._load_processor.cache_clear()
    try:
        assert acceleration.get_processor(algorithm) is None
    finally:
        acceleration._load_processor.cache_clear()


@pytest.mark.parametrize("implementation", [SHA256, SHA3_256])
def test_default_io_chunk_reaches_compiled_processor(implementation, monkeypatch):
    """8192 не кратно rate SHA3: неполный блок не должен выключать JIT."""
    calls = []

    def processor(state, data):
        calls.append(len(data))
        return state

    module = import_module(implementation.__module__)
    monkeypatch.setattr(module, "get_processor", lambda name: processor)
    implementation().update(bytes(8192))
    assert calls
    assert calls[0] <= 8192
