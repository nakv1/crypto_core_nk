"""Интерфейс командной строки CryptoCore."""

import argparse
import os
import sys
from collections.abc import Sequence

from cryptocore.file_io import read_file, write_file
from cryptocore.modes.cbc import CiphertextLengthError as CbcCiphertextLengthError
from cryptocore.modes.cbc import decrypt as decrypt_cbc
from cryptocore.modes.cbc import encrypt as encrypt_cbc
from cryptocore.modes.cfb import decrypt as decrypt_cfb
from cryptocore.modes.cfb import encrypt as encrypt_cfb
from cryptocore.modes.ctr import decrypt as decrypt_ctr
from cryptocore.modes.ctr import encrypt as encrypt_ctr
from cryptocore.modes.ecb import CiphertextLengthError as EcbCiphertextLengthError
from cryptocore.modes.ecb import decrypt as decrypt_ecb
from cryptocore.modes.ecb import encrypt as encrypt_ecb
from cryptocore.modes.ofb import decrypt as decrypt_ofb
from cryptocore.modes.ofb import encrypt as encrypt_ofb
from cryptocore.padding import PaddingError


MODE_ENCRYPTORS = {
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}

MODE_DECRYPTORS = {
    "cbc": decrypt_cbc,
    "cfb": decrypt_cfb,
    "ofb": decrypt_ofb,
    "ctr": decrypt_ctr,
}


def parse_key(value: str) -> bytes:
    """Проверка и преобразование ключа AES-128."""
    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            "key must contain exactly 32 hexadecimal characters"
        )
    if any(character not in "0123456789abcdefABCDEF" for character in value):
        raise argparse.ArgumentTypeError(
            "key must contain only hexadecimal characters (0-9, a-f, A-F)"
        )
    return bytes.fromhex(value)


def parse_iv(value: str) -> bytes:
    """Проверка и преобразование вектора инициализации AES."""
    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            "iv must contain exactly 32 hexadecimal characters"
        )
    if any(character not in "0123456789abcdefABCDEF" for character in value):
        raise argparse.ArgumentTypeError(
            "iv must contain only hexadecimal characters (0-9, a-f, A-F)"
        )
    return bytes.fromhex(value)


def build_encryption_parser() -> argparse.ArgumentParser:
    """Создание парсера аргументов шифрования."""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Encrypt or decrypt files with AES-128.",
    )
    parser.add_argument("--algorithm", choices=["aes"], required=True)
    parser.add_argument(
        "--mode", choices=["ecb", "cbc", "cfb", "ofb", "ctr"], required=True
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", type=parse_key, required=True)
    parser.add_argument("--iv", type=parse_iv)
    parser.add_argument("--input", required=True, dest="input_path")
    parser.add_argument("--output", required=True, dest="output_path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Запуск CLI и возврат кода завершения."""
    parser = build_encryption_parser()
    args = parser.parse_args(argv)

    if args.iv is not None and args.encrypt:
        parser.error("--iv can only be used with --decrypt")
    if args.iv is not None and args.mode == "ecb":
        parser.error("--iv is not supported for ECB")

    try:
        input_data = read_file(args.input_path)
    except FileNotFoundError:
        print(
            f"error: input file not found: {args.input_path}",
            file=sys.stderr,
        )
        return 1
    except PermissionError:
        print(
            f"error: permission denied while reading: {args.input_path}",
            file=sys.stderr,
        )
        return 1
    except OSError:
        print(f"error: cannot read input file: {args.input_path}", file=sys.stderr)
        return 1

    try:
        if args.encrypt:
            if args.mode == "ecb":
                output_data = encrypt_ecb(args.key, input_data)
            else:
                iv = os.urandom(16)
                ciphertext = MODE_ENCRYPTORS[args.mode](args.key, iv, input_data)
                output_data = iv + ciphertext
        else:
            if args.mode == "ecb":
                output_data = decrypt_ecb(args.key, input_data)
            else:
                if args.iv is not None:
                    iv = args.iv
                    ciphertext = input_data
                else:
                    if len(input_data) < 16:
                        print(
                            "error: input file is too short to contain a "
                            f"16-byte IV: {args.input_path}",
                            file=sys.stderr,
                        )
                        return 1
                    iv = input_data[:16]
                    ciphertext = input_data[16:]
                output_data = MODE_DECRYPTORS[args.mode](args.key, iv, ciphertext)
    except PaddingError:
        print(
            "error: invalid padding (wrong key or corrupted data)",
            file=sys.stderr,
        )
        return 1
    except (EcbCiphertextLengthError, CbcCiphertextLengthError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        write_file(args.output_path, output_data)
    except FileNotFoundError:
        print(
            f"error: output directory does not exist: {args.output_path}",
            file=sys.stderr,
        )
        return 1
    except PermissionError:
        print(
            f"error: permission denied while writing: {args.output_path}",
            file=sys.stderr,
        )
        return 1
    except OSError:
        print(f"error: cannot write output file: {args.output_path}", file=sys.stderr)
        return 1

    return 0
