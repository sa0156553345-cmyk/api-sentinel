#!/usr/bin/env python3
"""Run every test in this repository with the standard library only (pytest is optional).

    python3 tests/run_all.py

A test is a module-level function named test_* in a tests/test_*.py file. It passes when it returns normally.
Exit code: 0 when every test passes, 1 otherwise. `python3 -m pytest tests` also works if pytest is installed.
"""
from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # the api_sentinel module
sys.path.insert(0, str(HERE))         # helper modules that sit next to the tests


def main() -> int:
    passed = failed = 0
    for path in sorted(HERE.glob("test_*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in sorted(dir(module)):
            fn = getattr(module, name)
            if not (name.startswith("test_") and callable(fn)):
                continue
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL  {path.name}::{name}")
                traceback.print_exc()
            else:
                passed += 1
                print(f"PASS  {path.name}::{name}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
