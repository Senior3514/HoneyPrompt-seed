"""The checked-in example runs offline."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_phase1_example_runs_without_network():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("HONEYPROMPTS_SIGNING_KEY", None)
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "phase1_flow.py")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "trap stopped" in result.stdout
    assert "clean receipt" in result.stdout
    assert "AKIA-HONEY-" not in result.stdout
