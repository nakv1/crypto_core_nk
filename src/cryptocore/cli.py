"""Интерфейс командной строки CryptoCore."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from secrets import compare_digest

from cryptocore import csprng
from cryptocore.aead import AuthenticationError
from cryptocore.aead.files import decrypt_file as decrypt_gcm_file
from cryptocore.aead.files import encrypt_file as encrypt_gcm_file
from cryptocore.file_io import atomic_output, iter_chunks, read_file, write_file, write_file_exclusive
from cryptocore.hash import SHA256, SHA3_256
from cryptocore.kdf import pbkdf2_hmac_sha256
from cryptocore.kdf._validation import MAX_KEY_BYTES
from cryptocore.mac import CMAC, HMAC
from cryptocore.mac.verification import read_expected_mac
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

HASH_ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
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


def parse_mac_key(value: str) -> bytes:
    """Разбор hex-ключа MAC без ограничения длины AES-128."""
    if len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise argparse.ArgumentTypeError("MAC key must contain an even number of hexadecimal characters")
    return bytes.fromhex(value)


def parse_aad(value: str) -> bytes:
    """Строгий hex, включая пустую строку, без пробелов и префикса 0x."""
    if len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise argparse.ArgumentTypeError("AAD must contain an even number of hexadecimal characters")
    return bytes.fromhex(value)


def parse_nonce(value: str) -> bytes:
    if len(value) != 24 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise argparse.ArgumentTypeError("GCM nonce must contain exactly 24 hexadecimal characters")
    return bytes.fromhex(value)


def is_predictable_key(key: bytes) -> bool:
    """Проверка ключа на простые предсказуемые последовательности."""
    repeated = len(set(key)) == 1
    increasing = all(next_byte == byte + 1 for byte, next_byte in zip(key, key[1:]))
    decreasing = all(next_byte == byte - 1 for byte, next_byte in zip(key, key[1:]))
    return repeated or increasing or decreasing


def build_encryption_parser() -> argparse.ArgumentParser:
    """Создание парсера аргументов шифрования."""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Encrypt or decrypt files with AES-128.",
        epilog='For hashing use "cryptocore dgst"; for key derivation use "cryptocore derive".',
    )
    parser.add_argument("--algorithm", choices=["aes"], required=True)
    parser.add_argument(
        "--mode", choices=["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"], required=True
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", type=parse_key)
    initialization = parser.add_mutually_exclusive_group()
    initialization.add_argument("--iv", help="IV for decryption; GCM alias for --nonce")
    initialization.add_argument("--nonce", type=parse_nonce, help="12-byte GCM nonce for decryption")
    associated = parser.add_mutually_exclusive_group()
    associated.add_argument("--aad", type=parse_aad, help="GCM associated data in hexadecimal")
    associated.add_argument("--aad-file", help="read binary GCM associated data in chunks")
    parser.add_argument("--input", required=True, dest="input_path")
    parser.add_argument("--output", dest="output_path")
    return parser


def build_digest_parser() -> argparse.ArgumentParser:
    """Создание парсера аргументов хеширования."""
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Calculate a file digest.",
    )
    parser.add_argument(
        "--algorithm", choices=[*HASH_ALGORITHMS, "aes"]
    )
    mac_mode = parser.add_mutually_exclusive_group()
    mac_mode.add_argument("--hmac", action="store_true", help="calculate HMAC-SHA256")
    mac_mode.add_argument("--cmac", action="store_true", help="calculate AES-128-CMAC")
    parser.add_argument("--key", type=parse_mac_key, help="MAC key in hexadecimal")
    parser.add_argument("--input", required=True, dest="input_path")
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--output", dest="output_path")
    destination.add_argument("--verify", dest="verify_path", help="verify a saved MAC")
    return parser


def _run_digest(argv: Sequence[str]) -> int:
    """Вычисление хеша файла или стандартного ввода."""
    parser = build_digest_parser()
    args = parser.parse_args(argv)
    is_mac = args.hmac or args.cmac
    if is_mac:
        if args.key is None:
            parser.error("--key is required with --hmac or --cmac")
        if args.hmac:
            if args.algorithm not in (None, "sha256"):
                parser.error("--hmac supports only --algorithm sha256")
            hash_object = HMAC(args.key)
        else:
            if args.algorithm not in (None, "aes"):
                parser.error("--cmac supports only --algorithm aes")
            if len(args.key) != 16:
                parser.error("AES-CMAC key must contain exactly 32 hexadecimal characters")
            hash_object = CMAC(args.key)
    else:
        if args.verify_path is not None:
            parser.error("--verify requires --hmac or --cmac")
        if args.key is not None:
            parser.error("--key requires --hmac or --cmac")
        if args.algorithm not in HASH_ALGORITHMS:
            parser.error("--algorithm is required")
        hash_object = HASH_ALGORITHMS[args.algorithm]()

    try:
        if args.input_path == "-":
            for chunk in iter_chunks(sys.stdin.buffer):
                hash_object.update(chunk)
        else:
            with Path(args.input_path).open("rb") as input_file:
                for chunk in iter_chunks(input_file):
                    hash_object.update(chunk)
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

    if args.verify_path is not None:
        return _verify_mac(args.verify_path, hash_object.digest(), "HMAC" if args.hmac else "CMAC")

    separator = " " if is_mac else "  "
    result = f"{hash_object.hexdigest()}{separator}{args.input_path}\n"
    if args.output_path is None:
        print(result, end="")
        return 0

    try:
        write_file(args.output_path, result.encode("utf-8"))
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


def _verify_mac(path: str, actual: bytes, label: str) -> int:
    """Проверяет полный MAC и сообщает только об общем результате."""
    try:
        expected = read_expected_mac(path, len(actual))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: cannot read expected MAC: {error}", file=sys.stderr)
        return 1
    if compare_digest(actual, expected):
        print(f"[OK] {label} verification successful")
        return 0
    print(f"[ERROR] {label} verification failed", file=sys.stderr)
    return 1


def _file_aad(path):
    with Path(path).open("rb") as source:
        yield from iter_chunks(source)


def _positive_argument(value):
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _derive_length(value):
    parsed = _positive_argument(value)
    if parsed > MAX_KEY_BYTES:
        raise argparse.ArgumentTypeError("length exceeds the 32-bit block counter limit")
    return parsed


def _parse_salt(value):
    if len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise argparse.ArgumentTypeError("salt must contain an even number of hexadecimal characters")
    return bytes.fromhex(value)


def build_derive_parser():
    parser = argparse.ArgumentParser(prog="cryptocore derive", description="Derive a key with PBKDF2-HMAC-SHA256.")
    password = parser.add_mutually_exclusive_group(required=True)
    password.add_argument("--password", help="password encoded as UTF-8")
    password.add_argument("--password-file", help="read exact binary password bytes, including newlines")
    password.add_argument("--password-env", help="name of an environment variable containing the password")
    parser.add_argument("--salt", type=_parse_salt, help="hexadecimal salt; default: random 16 bytes")
    parser.add_argument("--iterations", type=_positive_argument, default=100000)
    parser.add_argument("--length", type=_derive_length, default=32)
    parser.add_argument("--algorithm", choices=["pbkdf2"], default="pbkdf2")
    parser.add_argument("--output", dest="output_path", help="write raw key bytes; stdout still includes key and salt")
    return parser


def _run_derive(argv):
    args = build_derive_parser().parse_args(argv)
    password = bytearray()
    try:
        if args.password_file is not None:
            password.extend(read_file(args.password_file))
        elif args.password_env is not None:
            value = os.environ.get(args.password_env)
            if value is None:
                raise ValueError("password environment variable is not set")
            password.extend(value.encode("utf-8"))
            del value
        else:
            password.extend(args.password.encode("utf-8"))
        args.password = None
        salt = args.salt if args.salt is not None else csprng.generate_random_bytes(16)
        key = pbkdf2_hmac_sha256(password, salt, args.iterations, args.length)
    except (OSError, ValueError, UnicodeError, csprng.RandomGenerationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        # Удаляет нашу изменяемую копию; Python/argv/env могут хранить другие копии.
        password[:] = bytes(len(password))
        args.password = None
    if args.output_path is not None:
        try:
            with atomic_output(args.output_path) as output:
                output.write(key)
        except OSError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    print(f"{key.hex()}  {salt.hex()}")
    return 0


def _run_gcm(args, automatic_output):
    if automatic_output and Path(args.output_path).exists():
        print(f"error: output file already exists: {args.output_path}", file=sys.stderr)
        return 1
    aad = _file_aad(args.aad_file) if args.aad_file is not None else (args.aad or b"")
    generated = args.key is None
    try:
        if generated:
            args.key = csprng.generate_random_bytes(16)
        elif is_predictable_key(args.key):
            print("warning: key looks predictable", file=sys.stderr)
        if args.encrypt:
            encrypt_gcm_file(args.key, args.input_path, args.output_path, aad,
                             exclusive=automatic_output)
        else:
            decrypt_gcm_file(args.key, args.input_path, args.output_path, aad,
                             nonce=args.nonce if args.nonce is not None else args.iv,
                             exclusive=automatic_output)
    except AuthenticationError:
        print("[ERROR] Authentication failed: wrong key, AAD, or tampered data", file=sys.stderr)
        return 1
    except (OSError, ValueError, csprng.RandomGenerationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if generated:
        print(f"[INFO] Generated random key: {args.key.hex()}")
    if args.decrypt:
        print("[SUCCESS] Decryption completed successfully")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Запуск CLI и возврат кода завершения."""
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "dgst":
        return _run_digest(argv[1:])
    if argv and argv[0] == "derive":
        return _run_derive(argv[1:])

    parser = build_encryption_parser()
    args = parser.parse_args(argv)

    if args.decrypt and args.key is None:
        parser.error("--key is required with --decrypt")
    if args.nonce is not None:
        if args.mode != "gcm":
            parser.error("--nonce is supported only for GCM")
        if args.encrypt:
            parser.error("--nonce can only be used with --decrypt")
    if args.mode != "gcm" and (args.aad is not None or args.aad_file is not None):
        parser.error("--aad and --aad-file require --mode gcm")
    if args.iv is not None:
        try:
            args.iv = parse_nonce(args.iv) if args.mode == "gcm" else parse_iv(args.iv)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
    if args.iv is not None and args.encrypt:
        parser.error("--iv can only be used with --decrypt")
    if args.iv is not None and args.mode == "ecb":
        parser.error("--iv is not supported for ECB")

    automatic_output = args.output_path is None
    if automatic_output:
        suffix = ".enc" if args.encrypt else ".dec"
        args.output_path = f"{args.input_path}{suffix}"

    if args.mode == "gcm":
        return _run_gcm(args, automatic_output)

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

    if automatic_output and Path(args.output_path).exists():
        print(
            f"error: output file already exists: {args.output_path}",
            file=sys.stderr,
        )
        return 1

    if args.key is not None and is_predictable_key(args.key):
        print("warning: key looks predictable", file=sys.stderr)

    try:
        if args.encrypt:
            if args.mode == "ecb":
                if args.key is None:
                    args.key = csprng.generate_random_bytes(16)
                    print(f"[INFO] Generated random key: {args.key.hex()}")
                output_data = encrypt_ecb(args.key, input_data)
            else:
                iv = csprng.generate_random_bytes(16)
                if args.key is None:
                    args.key = csprng.generate_random_bytes(16)
                    print(f"[INFO] Generated random key: {args.key.hex()}")
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
    except csprng.RandomGenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
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
        if automatic_output:
            write_file_exclusive(args.output_path, output_data)
        else:
            write_file(args.output_path, output_data)
    except FileExistsError:
        print(
            f"error: output file already exists: {args.output_path}",
            file=sys.stderr,
        )
        return 1
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
