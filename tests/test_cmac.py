import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from cryptocore.cli import main
from cryptocore.mac import CMAC

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)


@pytest.mark.parametrize(("length", "expected"), [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (20, "7d85449ea6ea19c823a7bf78837dfade"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
])
def test_nist_cmac_vectors(length, expected):
    mac = CMAC(KEY)
    mac.update(MESSAGE[:length])
    assert mac.hexdigest() == expected
    assert mac.compute(MESSAGE[:length]) == expected


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 33, 1000])
@pytest.mark.parametrize("chunk_size", [1, 7, 16, 17, 8192])
def test_streaming_boundaries(length, chunk_size):
    data = bytes(i % 256 for i in range(length))
    mac = CMAC(KEY)
    for start in range(0, len(data), chunk_size):
        mac.update(data[start:start + chunk_size])
    reference = ReferenceCMAC.new(KEY, msg=data, ciphermod=AES)
    assert mac.digest() == reference.digest()
    assert mac.digest() == reference.digest()
    assert len(mac._buffer) <= 16
    mac.update(b"suffix")
    assert mac.digest() == ReferenceCMAC.new(KEY, msg=data + b"suffix", ciphermod=AES).digest()


@pytest.mark.parametrize("key", [b"", bytes(15), bytes(17), bytes(32)])
def test_wrong_key_length(key):
    with pytest.raises(ValueError, match="exactly 16 bytes"):
        CMAC(key)


def test_invalid_types():
    with pytest.raises(TypeError):
        CMAC("key")
    with pytest.raises(TypeError):
        CMAC(KEY).update("text")


def test_cmac_cli_generate_verify_and_tamper(tmp_path, capsys):
    data = tmp_path / "input.bin"
    tag = tmp_path / "mac.txt"
    data.write_bytes(MESSAGE)
    args = ["dgst", "--cmac", "--algorithm", "aes", "--key", KEY.hex(), "--input", str(data)]
    assert main(args + ["--output", str(tag)]) == 0
    assert tag.read_text() == f"51f0bebf7e3b9d92fc49741779363cfe {data}\n"
    assert main(args + ["--verify", str(tag)]) == 0
    data.write_bytes(MESSAGE + b"x")
    assert main(args + ["--verify", str(tag)]) == 1
    assert "CMAC verification failed" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [
    ["--cmac"], ["--cmac", "--key", "00"],
    ["--cmac", "--hmac", "--key", KEY.hex()],
    ["--cmac", "--algorithm", "sha256", "--key", KEY.hex()],
    ["--algorithm", "aes"],
])
def test_invalid_cmac_arguments(extra):
    with pytest.raises(SystemExit) as error:
        main(["dgst", "--input", "missing"] + extra)
    assert error.value.code == 2
