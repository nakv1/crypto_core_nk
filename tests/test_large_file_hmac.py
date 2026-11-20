import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(os.environ.get("CRYPTOCORE_RUN_LARGE_TESTS") != "1",
                    reason="set CRYPTOCORE_RUN_LARGE_TESTS=1 to run limited-memory HMAC")
def test_hmac_file_exceeds_process_memory_limit():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts/check_large_hmac.py")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["matched"]
    assert report["whole_file_allocation_failed"]
    assert report["size_bytes"] > report["limit_bytes"]
    if "peak_committed_bytes" in report:
        assert report["peak_committed_bytes"] <= report["limit_bytes"]
    print(json.dumps(report))
