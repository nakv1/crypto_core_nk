import pytest
import subprocess

from cryptocore.kdf import pbkdf2_hmac_sha256
from test_openssl_compatibility import _find_openssl


@pytest.fixture(scope="module")
def openssl():
    return _find_openssl()


@pytest.mark.parametrize("password,salt", [(b"password", b"salt"), (b"pass\x00word", b"sa\x00lt"),
                                          (bytes(range(131)), bytes(range(65))), (b"", b"")])
@pytest.mark.parametrize("iterations", [1, 2, 1000])
@pytest.mark.parametrize("length", [1, 32, 65])
def test_openssl_pbkdf2_sha256(openssl, password, salt, iterations, length):
    command = [openssl, "kdf", "-keylen", str(length), "-kdfopt", "digest:SHA256",
               "-kdfopt", "hexpass:" + password.hex(), "-kdfopt", "hexsalt:" + salt.hex(),
               "-kdfopt", "iter:" + str(iterations), "PBKDF2"]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    expected = bytes.fromhex(result.stdout.replace(":", "").strip())
    assert pbkdf2_hmac_sha256(password, salt, iterations, length) == expected
