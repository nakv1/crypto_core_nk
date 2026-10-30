import hashlib
import io

import pytest

from cryptocore.cli import main


ALGORITHMS = [
    ("sha256", hashlib.sha256),
    ("sha3-256", hashlib.sha3_256),
]


def dgst_arguments(algorithm, input_path, output_path=None):
    arguments = [
        "dgst",
        "--algorithm",
        algorithm,
        "--input",
        str(input_path),
    ]
    if output_path is not None:
        arguments.extend(["--output", str(output_path)])
    return arguments


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
@pytest.mark.parametrize("data", [b"ordinary file data", b""], ids=["data", "empty"])
def test_dgst_hashes_file_with_exact_stdout_format(
    algorithm, reference, data, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(data)

    result = main(dgst_arguments(algorithm, input_path))

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == f"{reference(data).hexdigest()}  {input_path}\n"
    assert captured.err == ""


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_preserves_relative_input_path(
    algorithm, reference, tmp_path, monkeypatch, capsys
):
    input_path = tmp_path / "relative.bin"
    data = b"relative path"
    input_path.write_bytes(data)
    monkeypatch.chdir(tmp_path)

    result = main(dgst_arguments(algorithm, input_path.name))

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == f"{reference(data).hexdigest()}  relative.bin\n"
    assert captured.err == ""


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_writes_lf_output_and_keeps_stdout_empty(
    algorithm, reference, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "digest.txt"
    data = b"output file"
    input_path.write_bytes(data)

    result = main(dgst_arguments(algorithm, input_path, output_path))

    captured = capsys.readouterr()
    expected = f"{reference(data).hexdigest()}  {input_path}\n".encode()
    assert result == 0
    assert captured.out == ""
    assert captured.err == ""
    assert output_path.read_bytes() == expected
    assert b"\r" not in output_path.read_bytes()


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_overwrites_existing_output(
    algorithm, reference, tmp_path, capsys
):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "digest.txt"
    data = b"replacement digest"
    input_path.write_bytes(data)
    output_path.write_bytes(b"old output")

    result = main(dgst_arguments(algorithm, input_path, output_path))

    assert result == 0
    assert output_path.read_bytes() == (
        f"{reference(data).hexdigest()}  {input_path}\n".encode()
    )
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_allows_same_input_and_output_path(
    algorithm, reference, tmp_path, capsys
):
    path = tmp_path / "same.bin"
    original = b"hash before replacing the file"
    path.write_bytes(original)

    result = main(dgst_arguments(algorithm, path, path))

    assert result == 0
    assert path.read_bytes() == f"{reference(original).hexdigest()}  {path}\n".encode()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_reads_stdin(algorithm, reference, monkeypatch, capsys):
    data = b"data from stdin"

    class Stdin:
        buffer = io.BytesIO(data)

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())

    result = main(dgst_arguments(algorithm, "-"))

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == f"{reference(data).hexdigest()}  -\n"
    assert captured.err == ""


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_missing_input_does_not_create_output(
    algorithm, tmp_path, capsys
):
    input_path = tmp_path / "missing.bin"
    output_path = tmp_path / "digest.txt"

    result = main(dgst_arguments(algorithm, input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert not output_path.exists()


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_missing_input_does_not_modify_existing_output(
    algorithm, tmp_path, capsys
):
    input_path = tmp_path / "missing.bin"
    output_path = tmp_path / "digest.txt"
    original_output = b"keep existing output"
    output_path.write_bytes(original_output)

    result = main(dgst_arguments(algorithm, input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert output_path.read_bytes() == original_output


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_read_error_does_not_modify_existing_output(
    algorithm, tmp_path, monkeypatch, capsys
):
    output_path = tmp_path / "digest.txt"
    original_output = b"keep existing output"
    output_path.write_bytes(original_output)

    class FailingStream:
        def __init__(self):
            self.read_count = 0

        def read(self, size):
            assert size == 8192
            self.read_count += 1
            if self.read_count == 1:
                return b"first chunk"
            raise OSError("simulated read error")

    class Stdin:
        buffer = FailingStream()

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())

    result = main(dgst_arguments(algorithm, "-", output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert "Traceback" not in captured.err
    assert output_path.read_bytes() == original_output


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_rejects_directory_as_input(algorithm, tmp_path, capsys):
    result = main(dgst_arguments(algorithm, tmp_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err


@pytest.mark.parametrize("algorithm", ["sha256", "sha3-256"])
def test_dgst_reports_output_write_error(algorithm, tmp_path, capsys):
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "missing" / "digest.txt"
    input_path.write_bytes(b"input data")

    result = main(dgst_arguments(algorithm, input_path, output_path))

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert not output_path.exists()


@pytest.mark.parametrize(
    "foreign_arguments",
    [
        ["--key", "00" * 16],
        ["--mode", "cbc"],
        ["--encrypt"],
        ["--decrypt"],
        ["--iv", "00" * 16],
    ],
    ids=["key", "mode", "encrypt", "decrypt", "iv"],
)
def test_dgst_rejects_encryption_arguments(foreign_arguments, tmp_path, capsys):
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"data")
    arguments = dgst_arguments("sha256", input_path) + foreign_arguments

    with pytest.raises(SystemExit) as error:
        main(arguments)

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_dgst_rejects_unknown_algorithm(tmp_path, capsys):
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"data")

    with pytest.raises(SystemExit) as error:
        main(dgst_arguments("unknown", input_path))

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_dgst_requires_input(capsys):
    with pytest.raises(SystemExit) as error:
        main(["dgst", "--algorithm", "sha256"])

    assert error.value.code == 2
    assert "--input" in capsys.readouterr().err


def test_dgst_help_lists_arguments(capsys):
    with pytest.raises(SystemExit) as error:
        main(["dgst", "--help"])

    captured = capsys.readouterr()
    assert error.value.code == 0
    assert captured.err == ""
    assert "--algorithm" in captured.out
    assert "--input" in captured.out
    assert "--output" in captured.out


def test_encryption_help_mentions_dgst(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    captured = capsys.readouterr()
    assert error.value.code == 0
    assert "cryptocore dgst" in captured.out


@pytest.mark.parametrize(("algorithm", "reference"), ALGORITHMS)
def test_dgst_reads_stream_in_bounded_chunks(
    algorithm, reference, monkeypatch, capsys
):
    data = bytes((index * 17 + 3) % 256 for index in range(20_000))

    class RecordingStream:
        def __init__(self):
            self.stream = io.BytesIO(data)
            self.read_sizes = []

        def read(self, size):
            assert size > 0
            self.read_sizes.append(size)
            return self.stream.read(size)

    stream = RecordingStream()

    class Stdin:
        buffer = stream

    monkeypatch.setattr("cryptocore.cli.sys.stdin", Stdin())

    result = main(dgst_arguments(algorithm, "-"))

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == f"{reference(data).hexdigest()}  -\n"
    assert stream.read_sizes
    assert all(size <= 8192 for size in stream.read_sizes)

def test_dgst_requires_algorithm(tmp_path, capsys):
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"data")

    with pytest.raises(SystemExit) as error:
        main(["dgst", "--input", str(input_path)])

    assert error.value.code == 2
    assert "--algorithm" in capsys.readouterr().err