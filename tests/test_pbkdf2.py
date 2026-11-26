"""PBKDF2-HMAC-SHA256: RFC 7914 §11 и независимый hashlib."""

import hashlib
from importlib import import_module
from importlib.util import find_spec

import pytest

from cryptocore.kdf import pbkdf2_hmac_sha256
from cryptocore.kdf._validation import MAX_KEY_BYTES


@pytest.mark.parametrize("password,salt,iterations,expected", [
    (b"passwd", b"salt", 1,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
    (b"Password", b"NaCl", 80000,
     "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
     "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
])
def test_rfc7914_sha256_vectors(password, salt, iterations, expected):
    assert pbkdf2_hmac_sha256(password, salt, iterations, 64).hex() == expected


@pytest.mark.parametrize("iterations,expected", [
    (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
    (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
    (4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
])
def test_known_sha256_answers(iterations, expected):
    assert pbkdf2_hmac_sha256(b"password", b"salt", iterations).hex() == expected


@pytest.mark.parametrize("length", range(1, 101))
def test_every_output_length_one_to_one_hundred(length):
    actual = pbkdf2_hmac_sha256(b"password", b"salt", 2, length)
    assert len(actual) == length
    assert actual == hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2, length)


@pytest.mark.parametrize("password_length", [0, 1, 63, 64, 65, 131, 4097])
@pytest.mark.parametrize("salt_length", [0, 1, 51, 52, 55, 56, 63, 64, 65, 100, 4097])
def test_password_and_salt_boundaries(password_length, salt_length):
    password = (bytes(range(256)) * 17)[:password_length]
    salt = (bytes(range(255, -1, -1)) * 17)[:salt_length]
    actual = pbkdf2_hmac_sha256(password, salt, 3, 33)
    assert actual == hashlib.pbkdf2_hmac("sha256", password, salt, 3, 33)


@pytest.mark.parametrize("password,salt,length", [
    (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 25),
    (b"pass\x00word", b"sa\x00lt", 16),
])
def test_rfc6070_inputs_with_sha256_not_sha1(password, salt, length):
    assert pbkdf2_hmac_sha256(password, salt, 4096, length) == hashlib.pbkdf2_hmac(
        "sha256", password, salt, 4096, length)


def test_utf8_and_mutable_inputs():
    password = "Пароль🔐\x00"
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 2)
    assert pbkdf2_hmac_sha256(password, b"salt", 2) == expected
    for kind in [bytes, bytearray, memoryview]:
        actual = pbkdf2_hmac_sha256(kind(password.encode()), kind(b"salt"), 2)
        assert actual == expected


@pytest.mark.parametrize("iterations", [1000, 1001])
@pytest.mark.parametrize("length", [1, 33, 65])
@pytest.mark.parametrize("password", [b"", b"x" * 65])
def test_python_and_compiled_chains_match(iterations, length, password, monkeypatch):
    if find_spec("numba") is None:
        pytest.skip("install cryptocore[speed] to test compiled PBKDF2")
    salt = b"s" * 52
    monkeypatch.setenv("CRYPTOCORE_PURE_PYTHON", "1")
    pure = pbkdf2_hmac_sha256(password, salt, iterations, length)
    monkeypatch.setenv("CRYPTOCORE_PURE_PYTHON", "0")
    accelerated = pbkdf2_hmac_sha256(password, salt, iterations, length)
    assert pure == accelerated == hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length)


def test_one_million_iterations_with_multiple_blocks(monkeypatch):
    if find_spec("numba") is None:
        pytest.skip("install cryptocore[speed] to test a million compiled iterations")
    monkeypatch.setenv("CRYPTOCORE_PURE_PYTHON", "0")
    actual = pbkdf2_hmac_sha256(b"password" * 10, b"salt" * 20, 1000000, 65)
    assert actual == hashlib.pbkdf2_hmac("sha256", b"password" * 10, b"salt" * 20, 1000000, 65)


def test_missing_compiler_falls_back_to_own_hmac(monkeypatch):
    module = import_module("cryptocore.kdf.pbkdf2")
    monkeypatch.delenv("CRYPTOCORE_PURE_PYTHON", raising=False)
    monkeypatch.setattr(module, "find_spec", lambda name: None)
    module._load_chain.cache_clear()
    try:
        assert module._get_chain(1000) is None
        actual = pbkdf2_hmac_sha256(b"password", b"salt", 1000)
        assert actual == hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)
    finally:
        module._load_chain.cache_clear()


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", None])
def test_invalid_iteration_count(value):
    with pytest.raises((TypeError, ValueError)):
        pbkdf2_hmac_sha256(b"p", b"s", value)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "32", None, MAX_KEY_BYTES + 1])
def test_invalid_length(value):
    with pytest.raises((TypeError, ValueError)):
        pbkdf2_hmac_sha256(b"p", b"s", 1, value)


@pytest.mark.parametrize("password,salt", [(None, b"s"), (42, b"s"), (b"p", "salt"), (b"p", None)])
def test_invalid_binary_arguments(password, salt):
    with pytest.raises(TypeError):
        pbkdf2_hmac_sha256(password, salt, 1)
