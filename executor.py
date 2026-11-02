import subprocess
import sys
import tempfile
from pathlib import Path


def execute_code(code):
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / "generated.py"
        file_path.write_text(code, encoding="utf-8")

        return run_python_file(file_path)


def execute_with_test_runner(code, test_runner):
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)

        generated_file = folder / "generated.py"
        runner_file = folder / "test_runner.py"

        generated_file.write_text(code, encoding="utf-8")
        runner_file.write_text(test_runner, encoding="utf-8")

        return run_python_file(runner_file)


def run_python_file(file_path):
    try:
        result = subprocess.run(
            [sys.executable, str(file_path)],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(file_path.parent)
        )

        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": "Execution timed out"
        }