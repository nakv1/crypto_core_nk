"""Генерация случайных данных для NIST STS."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from cryptocore import csprng


DEFAULT_SIZE = 10_000_000
CHUNK_SIZE = 64 * 1024


def generate_sts_data(output_path: str | Path, size: int) -> None:
    """Потоковая запись заданного объёма случайных данных в новый файл."""
    output_path = Path(output_path)
    output_file = output_path.open("xb")
    completed = False

    try:
        with output_file:
            remaining = size
            while remaining > 0:
                current_size = min(CHUNK_SIZE, remaining)
                data = csprng.generate_random_bytes(current_size)
                output_file.write(data)
                remaining -= current_size
        completed = True
    finally:
        if not completed:
            try:
                output_path.unlink()
            except OSError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    """Разбор аргументов и создание файла данных для NIST STS."""
    parser = argparse.ArgumentParser(
        description="Generate random binary data for NIST STS."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    args = parser.parse_args(argv)

    if args.size <= 0:
        parser.error("--size must be greater than zero")

    try:
        generate_sts_data(args.output, args.size)
    except FileExistsError:
        print(f"error: output file already exists: {args.output}", file=sys.stderr)
        return 1
    except csprng.RandomGenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(f"error: cannot create or write output file: {args.output}", file=sys.stderr)
        return 1

    print(f"Generated {args.size} bytes: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
