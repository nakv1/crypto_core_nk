import pytest

from cryptocore.padding import PaddingError, pad, unpad


@pytest.mark.parametrize(
    ("data", "expected_padding_length"),
    [
        (b"", 16),
        (b"abc", 13),
        (b"a" * 16, 16),
        (b"a" * 33, 15),
    ],
)
def test_pad_and_unpad(data, expected_padding_length):
    padded = pad(data)

    assert len(padded) % 16 == 0
    assert padded[-1] == expected_padding_length
    assert padded[-expected_padding_length:] == bytes([expected_padding_length]) * expected_padding_length
    assert unpad(padded) == data


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"A" * 15 + b"\x00",
        b"A" * 15 + b"\x11",
        b"A" * 14 + b"\x01\x02",
        b"not block aligned",
    ],
)
def test_unpad_rejects_invalid_padding(data):
    with pytest.raises(PaddingError):
        unpad(data)
