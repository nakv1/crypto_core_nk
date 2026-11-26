import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.environ.get("CRYPTOCORE_RUN_LARGE_TESTS") != "1",
                    reason="set CRYPTOCORE_RUN_LARGE_TESTS=1 to run limited-memory AAD")
def test_gcm_aad_exceeds_process_memory_limit():
    script = Path(__file__).resolve().parents[1] / "scripts/check_large_aad.py"
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["matched"]
    assert report["whole_aad_allocation_failed"]
    assert report["size_bytes"] > report["limit_bytes"]
    if "peak_committed_bytes" in report:
        assert report["peak_committed_bytes"] <= report["limit_bytes"]
    print(json.dumps(report))
