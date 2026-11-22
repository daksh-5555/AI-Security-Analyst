"""Regression tests for the test-environment override in ``tests/conftest.py``."""

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFTEST_PATH = PROJECT_ROOT / "tests" / "conftest.py"


def test_conftest_assigns_test_environment_before_application_imports() -> None:
    source = CONFTEST_PATH.read_text(encoding="utf-8")
    assignment = 'os.environ["APP_ENV"] = "test"'

    assert assignment in source
    assert 'os.environ.setdefault("APP_ENV", "test")' not in source

    assignment_index = source.index(assignment)
    first_app_import = min(
        index for index in (source.find("from app."), source.find("import app")) if index != -1
    )
    assert assignment_index < first_app_import


def test_conftest_overrides_existing_production_value() -> None:
    script = (
        "import json, os, runpy, sys\n"
        "namespace = runpy.run_path(sys.argv[1])\n"
        "print(json.dumps({\n"
        "    'environment': os.environ['APP_ENV'],\n"
        "    'settings': namespace['settings'].app_env,\n"
        "}))\n"
    )
    environment = {
        **os.environ,
        "APP_ENV": "production",
        "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT), os.environ.get("PYTHONPATH", "")]).rstrip(
            os.pathsep
        ),
    }

    result = subprocess.run(
        [sys.executable, "-c", script, str(CONFTEST_PATH)],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"environment": "test", "settings": "test"}
