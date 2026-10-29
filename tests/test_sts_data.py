import importlib.util
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, call

import pytest


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "generate_sts_data.py"


@pytest.fixture(scope="module")
def sts_script():
    spec = importlib.util.spec_from_file_location("generate_sts_data", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("size", [1, 64 * 1024, 64 * 1024 + 17])
def test_generate_sts_data_creates_file_of_requested_size(
    size, sts_script, tmp_path, monkeypatch
):
    output_path = tmp_path / "sts.bin"
    generator = Mock(side_effect=lambda chunk_size: b"x" * chunk_size)
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    sts_script.generate_sts_data(output_path, size)

    assert output_path.stat().st_size == size
    assert all(
        current_call.args[0] <= sts_script.CHUNK_SIZE
        for current_call in generator.call_args_list
    )


def test_generate_sts_data_uses_exact_chunk_sizes(sts_script, tmp_path, monkeypatch):
    output_path = tmp_path / "sts.bin"
    size = 2 * sts_script.CHUNK_SIZE + 123
    generator = Mock(side_effect=lambda chunk_size: b"x" * chunk_size)
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    sts_script.generate_sts_data(output_path, size)

    assert generator.call_args_list == [
        call(sts_script.CHUNK_SIZE),
        call(sts_script.CHUNK_SIZE),
        call(123),
    ]
    assert output_path.stat().st_size == size


def test_main_uses_default_size(sts_script, tmp_path, monkeypatch, capsys):
    output_path = tmp_path / "sts.bin"
    generate_file = Mock()
    monkeypatch.setattr(sts_script, "generate_sts_data", generate_file)

    result = sts_script.main([str(output_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert generate_file.call_args_list == [
        call(output_path, sts_script.DEFAULT_SIZE)
    ]
    assert str(output_path) in captured.out
    assert str(sts_script.DEFAULT_SIZE) in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("size", [0, -1])
def test_main_rejects_non_positive_size(
    size, sts_script, tmp_path, monkeypatch, capsys
):
    output_path = tmp_path / "sts.bin"
    generate_file = Mock()
    monkeypatch.setattr(sts_script, "generate_sts_data", generate_file)

    with pytest.raises(SystemExit) as error:
        sts_script.main([str(output_path), "--size", str(size)])

    assert error.value.code == 2
    assert generate_file.call_args_list == []
    assert "error:" in capsys.readouterr().err
    assert not output_path.exists()


def test_main_preserves_existing_output(sts_script, tmp_path, monkeypatch, capsys):
    output_path = tmp_path / "sts.bin"
    original = b"existing file"
    output_path.write_bytes(original)
    generator = Mock(side_effect=[])
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    result = sts_script.main([str(output_path), "--size", "10"])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert generator.call_args_list == []
    assert output_path.read_bytes() == original


def test_main_reports_missing_output_directory(
    sts_script, tmp_path, monkeypatch, capsys
):
    output_path = tmp_path / "missing" / "sts.bin"
    generator = Mock(side_effect=[])
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    result = sts_script.main([str(output_path), "--size", "10"])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "error:" in captured.err
    assert generator.call_args_list == []
    assert not output_path.exists()


def test_random_generation_error_removes_partial_file(
    sts_script, tmp_path, monkeypatch, capsys
):
    output_path = tmp_path / "sts.bin"
    error = sts_script.csprng.RandomGenerationError(
        "failed to generate random bytes"
    )
    generator = Mock(
        side_effect=[b"x" * sts_script.CHUNK_SIZE, error]
    )
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    result = sts_script.main(
        [str(output_path), "--size", str(sts_script.CHUNK_SIZE + 1)]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == [call(sts_script.CHUNK_SIZE), call(1)]
    assert captured.out == ""
    assert "error:" in captured.err
    assert not output_path.exists()


def test_keyboard_interrupt_removes_partial_file(
    sts_script, tmp_path, monkeypatch
):
    output_path = tmp_path / "sts.bin"
    generator = Mock(
        side_effect=[
            b"x" * sts_script.CHUNK_SIZE,
            KeyboardInterrupt(),
        ]
    )
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    with pytest.raises(KeyboardInterrupt):
        sts_script.generate_sts_data(
            output_path, sts_script.CHUNK_SIZE + 1
        )

    assert generator.call_args_list == [call(sts_script.CHUNK_SIZE), call(1)]
    assert not output_path.exists()


def test_write_error_removes_partial_file(sts_script, tmp_path, monkeypatch, capsys):
    output_path = tmp_path / "sts.bin"
    original_open = Path.open

    class FailingOutput:
        def __init__(self, path):
            self.file = original_open(path, "xb")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.file.close()

        def write(self, data):
            self.file.write(data[:1])
            raise OSError("simulated write error")

    def failing_open(path, mode):
        assert path == output_path
        assert mode == "xb"
        return FailingOutput(path)

    generator = Mock(side_effect=[b"x" * 10])
    monkeypatch.setattr(Path, "open", failing_open)
    monkeypatch.setattr(sts_script.csprng, "generate_random_bytes", generator)

    result = sts_script.main([str(output_path), "--size", "10"])

    captured = capsys.readouterr()
    assert result == 1
    assert generator.call_args_list == [call(10)]
    assert captured.out == ""
    assert "error:" in captured.err
    assert not output_path.exists()


def test_two_runs_generate_different_data(sts_script, tmp_path):
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"

    sts_script.generate_sts_data(first_path, 1024)
    sts_script.generate_sts_data(second_path, 1024)

    assert first_path.read_bytes() != second_path.read_bytes()


def test_script_smoke_run(tmp_path):
    output_path = tmp_path / "smoke.bin"
    size = 257

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(output_path), "--size", str(size)],
        capture_output=True,
        text=True,
        errors="replace",
    )

    assert result.returncode == 0, result.stderr
    assert output_path.stat().st_size == size
    assert str(output_path) in result.stdout
    assert str(size) in result.stdout
    assert result.stderr == ""
