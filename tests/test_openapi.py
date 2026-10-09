import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).parents[1]

def test_openapi_discovery():
    p = subprocess.run(
        [sys.executable, str(ROOT/"api_sentinel.py"),
         "--openapi", str(ROOT/"examples/openapi.json"),
         "--yes-i-am-authorized"],
        capture_output=True, text=True
    )
    assert p.returncode == 0
    assert "getOrder" in p.stdout
    assert "createOrder" in p.stdout
