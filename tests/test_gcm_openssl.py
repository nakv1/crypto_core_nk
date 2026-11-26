"""Независимая совместимость GCM через OpenSSL EVP, а не openssl enc."""

import ctypes as c
from ctypes.util import find_library
import os
from pathlib import Path

import pytest

from cryptocore.aead import AuthenticationError
from cryptocore.modes.gcm import decrypt, encrypt


@pytest.fixture(scope="module")
def libcrypto():
    override = os.environ.get("CRYPTOCORE_LIBCRYPTO")
    if override is not None:
        candidates = [override]
    else:
        candidates = [find_library("crypto")]
        if os.name == "nt":
            candidates += [str(path) for path in [
                Path(r"C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll"),
                Path(r"C:\Windows\System32\libcrypto.dll"),
            ] if path.is_file()]
    library = None
    errors = []
    for candidate in filter(None, candidates):
        try:
            library = c.CDLL(candidate)
            break
        except OSError as error:
            errors.append(str(error))
    if library is None:
        if override is not None or errors:
            pytest.fail("cannot load libcrypto: " + "; ".join(errors))
        pytest.skip("OpenSSL libcrypto not found; set CRYPTOCORE_LIBCRYPTO")
    signatures = {
        "EVP_CIPHER_CTX_new": (c.c_void_p, []),
        "EVP_CIPHER_CTX_free": (None, [c.c_void_p]),
        "EVP_aes_128_gcm": (c.c_void_p, []),
        "EVP_CIPHER_CTX_ctrl": (c.c_int, [c.c_void_p, c.c_int, c.c_int, c.c_void_p]),
    }
    for operation in ["Encrypt", "Decrypt"]:
        signatures[f"EVP_{operation}Init_ex"] = (
            c.c_int, [c.c_void_p, c.c_void_p, c.c_void_p, c.c_char_p, c.c_char_p])
        signatures[f"EVP_{operation}Update"] = (
            c.c_int, [c.c_void_p, c.c_void_p, c.POINTER(c.c_int), c.c_char_p, c.c_int])
        signatures[f"EVP_{operation}Final_ex"] = (
            c.c_int, [c.c_void_p, c.c_void_p, c.POINTER(c.c_int)])
    for name, (result_type, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result_type, arguments
    return library


def openssl_gcm(library, key, nonce, data, aad, tag=None):
    operation = "Encrypt" if tag is None else "Decrypt"
    initialize = getattr(library, f"EVP_{operation}Init_ex")
    update = getattr(library, f"EVP_{operation}Update")
    finalize = getattr(library, f"EVP_{operation}Final_ex")
    context = library.EVP_CIPHER_CTX_new()
    assert context
    try:
        assert initialize(context, library.EVP_aes_128_gcm(), None, None, None) == 1
        assert library.EVP_CIPHER_CTX_ctrl(context, 0x9, len(nonce), None) == 1
        assert initialize(context, None, None, key, nonce) == 1
        count = c.c_int()
        assert update(context, None, c.byref(count), aad, len(aad)) == 1
        output = c.create_string_buffer(len(data) + 16)
        assert update(context, output, c.byref(count), data, len(data)) == 1
        length = count.value
        if tag is not None:
            expected = c.create_string_buffer(tag, 16)
            assert library.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, expected) == 1
        verified = finalize(context, c.byref(output, length), c.byref(count))
        if verified != 1:
            raise AuthenticationError("OpenSSL authentication failed")
        result = output.raw[:length + count.value]
        if tag is None:
            generated = c.create_string_buffer(16)
            assert library.EVP_CIPHER_CTX_ctrl(context, 0x10, 16, generated) == 1
            return result + generated.raw
        return result
    finally:
        library.EVP_CIPHER_CTX_free(context)


@pytest.mark.parametrize("nonce_size", [8, 12, 16])
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 257])
@pytest.mark.parametrize("aad", [b"", b"metadata with partial block"])
def test_gcm_both_directions(libcrypto, nonce_size, size, aad):
    key, nonce, data = bytes(range(16)), bytes(range(nonce_size)), b"a" * size
    actual = encrypt(key, nonce, data, aad)
    assert openssl_gcm(libcrypto, key, nonce, actual[:-16], aad, actual[-16:]) == data
    expected = openssl_gcm(libcrypto, key, nonce, data, aad)
    assert actual == expected
    assert decrypt(key, nonce, expected, aad) == data
    with pytest.raises(AuthenticationError):
        openssl_gcm(libcrypto, key, nonce, actual[:-16], aad + b"x", actual[-16:])
