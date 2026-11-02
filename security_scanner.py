"""Evidence-preserving Bandit and pip-audit wrappers for ProofLoop."""
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

ALWAYS_EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", "dist", "build",
    "coverage", ".tox",
}
PRODUCTION_EXCLUDED_DIRS = {
    "tests", "test", "testing", "samples", "sample", "fixtures",
    "scanner_samples", "examples",
}
BACKUP_PATTERNS = (
    "*_backup.py", "*backup*.py", "*_before_*.py", "*_final.py",
    "*_updated.py", "*_fixed.py", "*.bak", "*.orig", "*~",
)


def _extract_json(stdout, expected_type):
    text = (stdout or "").strip()
    if not text:
        raise ValueError("Scanner returned empty stdout.")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start_char, end_char = ("{", "}") if expected_type is dict else ("[", "]")
        start, end = text.find(start_char), text.rfind(end_char)
        if start < 0 or end <= start:
            raise ValueError("Scanner output did not contain valid JSON.")
        payload = json.loads(text[start:end + 1])
    if not isinstance(payload, expected_type):
        raise ValueError(f"Unexpected scanner JSON type: expected {expected_type.__name__}.")
    return payload


def _run(command, *, cwd=None, timeout=180):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              cwd=str(cwd) if cwd else None, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Scanner timed out after {timeout} seconds.") from exc


def _python_targets(repo_path: Path, scan_scope: str):
    if scan_scope not in {"production", "full"}:
        raise ValueError("scan_scope must be 'production' or 'full'.")
    targets = []
    for path in repo_path.rglob("*.py"):
        rel = path.relative_to(repo_path)
        parts = {p.lower() for p in rel.parts[:-1]}
        if parts & ALWAYS_EXCLUDED_DIRS:
            continue
        if any(fnmatch.fnmatch(path.name.lower(), pat) for pat in BACKUP_PATTERNS):
            continue
        if scan_scope == "production" and parts & PRODUCTION_EXCLUDED_DIRS:
            continue
        if scan_scope == "production" and (path.name.lower().startswith("test_") or path.name.lower().endswith("_test.py")):
            continue
        targets.append(path)
    return sorted(targets)


def scan_repository(repository_path, scan_scope="production"):
    repo_path = Path(repository_path).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError("Repository path must be an existing directory.")
    targets = _python_targets(repo_path, scan_scope)
    if not targets:
        return {"scanner":"bandit", "repository":str(repo_path), "scan_scope":scan_scope,
                "files_scanned":0, "total_findings":0, "findings":[], "scanner_errors":[],
                "exit_code":0, "status":"completed", "note":"No eligible Python files were found."}
    command = [sys.executable, "-m", "bandit", "-f", "json", "-q", *map(str, targets)]
    result = _run(command, cwd=repo_path, timeout=240)
    try:
        report = _extract_json(result.stdout, dict)
    except (ValueError, json.JSONDecodeError) as exc:
        detail = (result.stderr or result.stdout or "No scanner output").strip()
        if "No module named bandit" in detail:
            detail += "\nInstall it in this environment with: python -m pip install bandit"
        raise RuntimeError(f"Could not parse Bandit output (exit {result.returncode}): {detail}") from exc
    findings, seen = [], set()
    for item in report.get("results", []):
        filename = str(item.get("filename") or "")
        try:
            filename = Path(filename).resolve().relative_to(repo_path).as_posix()
        except Exception:
            filename = Path(filename).as_posix()
        key = (item.get("test_id"), filename, item.get("line_number"),
               " ".join(str(item.get("code") or "").split()))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "tool":"bandit", "rule_id":item.get("test_id"), "title":item.get("test_name"),
            "description":item.get("issue_text"), "severity":str(item.get("issue_severity") or "").lower(),
            "confidence":str(item.get("issue_confidence") or "").lower(), "file":filename,
            "line":item.get("line_number"), "code":item.get("code"),
            "cwe":item.get("issue_cwe", {}), "reference":item.get("more_info"),
        })
    scanner_errors = report.get("errors", [])
    return {"scanner":"bandit", "repository":str(repo_path), "scan_scope":scan_scope,
            "files_scanned":len(targets), "total_findings":len(findings), "findings":findings,
            "scanner_errors":scanner_errors, "stderr":(result.stderr or "").strip(),
            "exit_code":result.returncode,
            "status":"completed_with_errors" if scanner_errors else "completed",
            "note":("Bandit returned findings (a non-zero exit code can be normal when findings exist)."
                    if result.returncode and findings else None)}


def scan_dependencies(requirements_file):
    requirements_path = Path(requirements_file).expanduser().resolve()
    if not requirements_path.exists() or not requirements_path.is_file():
        raise ValueError("Requirements file does not exist.")
    result = _run([sys.executable, "-m", "pip_audit", "-r", str(requirements_path), "-f", "json"],
                  cwd=requirements_path.parent, timeout=180)
    try:
        try:
            dependencies = _extract_json(result.stdout, list)
        except (ValueError, json.JSONDecodeError):
            dependencies = _extract_json(result.stdout, dict).get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ValueError("pip-audit JSON did not contain a dependency list.")
    except (ValueError, json.JSONDecodeError) as exc:
        detail = (result.stderr or result.stdout or "No scanner output").strip()
        if "No module named pip_audit" in detail:
            detail += "\nInstall it in this environment with: python -m pip install pip-audit"
        raise RuntimeError(f"Could not parse pip-audit output (exit {result.returncode}): {detail}") from exc
    findings=[]
    for item in dependencies:
        if isinstance(item,dict) and item.get("vulns"):
            findings.append({"tool":"pip-audit", "package":item.get("name"),
                             "installed_version":item.get("version"), "vulnerabilities":item.get("vulns")})
    return {"scanner":"pip-audit", "requirements_file":str(requirements_path),
            "total_packages_scanned":len(dependencies), "total_affected_packages":len(findings),
            "total_vulnerabilities":sum(len(x["vulnerabilities"]) for x in findings),
            "findings":findings, "exit_code":result.returncode, "status":"completed",
            "stderr":(result.stderr or "").strip(),
            "note":("pip-audit returned vulnerability records (a non-zero exit code can be normal when vulnerabilities exist)."
                    if result.returncode and findings else None)}


def run_full_security_scan(repository_path, requirements_file, scan_scope="production"):
    bandit_report=scan_repository(repository_path, scan_scope=scan_scope)
    dependency_report=scan_dependencies(requirements_file)
    return {"repository":str(Path(repository_path).expanduser().resolve()), "bandit":bandit_report,
            "dependencies":dependency_report, "summary":{"code_findings":bandit_report["total_findings"],
            "affected_packages":dependency_report["total_affected_packages"],
            "known_vulnerabilities":dependency_report["total_vulnerabilities"]}}
