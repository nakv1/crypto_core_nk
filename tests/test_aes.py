import pytest

from cryptocore.aes import decrypt_block, encrypt_block


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
BLOCK = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")


@pytest.mark.parametrize("operation", [encrypt_block, decrypt_block])
def test_block_operation_rejects_wrong_key_length(operation):
    with pytest.raises(ValueError):
        operation(b"short key", BLOCK)


@pytest.mark.parametrize("operation", [encrypt_block, decrypt_block])
def test_block_operation_rejects_wrong_block_length(operation):
    with pytest.raises(ValueError):
        operation(KEY, b"short block")
