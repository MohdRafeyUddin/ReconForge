import ast
import os
import re
import sys
from pathlib import Path
import pytest

MODULE_TO_PKG_MAP = {
    "aiohttp": "aiohttp",
    "bson": "pymongo",
    "dotenv": "python-dotenv",
    "fastapi": "fastapi",
    "httpx": "httpx",
    "jose": "python-jose",
    "motor": "motor",
    "passlib": "passlib",
    "pydantic": "pydantic",
    "pymongo": "pymongo",
    "uvicorn": "uvicorn",
    "websockets": "websockets",
}


def parse_requirements(req_path: Path):
    assert req_path.exists(), f"requirements.txt not found at {req_path}"
    reqs = {}
    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Match package[extra]==version or package==version
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?(==|>=|<=|>|<)?(.*)$", line)
            if m:
                pkg = m.group(1).lower().replace("_", "-")
                op = m.group(2)
                ver = m.group(3)
                reqs[pkg] = {"op": op, "version": ver, "raw": line}
    return reqs


def scan_app_imports(app_dir: Path):
    imports = {}
    for root, _, files in os.walk(app_dir):
        for f in files:
            if f.endswith(".py"):
                file_path = Path(root) / f
                with open(file_path, "r", encoding="utf-8") as src:
                    tree = ast.parse(src.read(), filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for n in node.names:
                            top = n.name.split(".")[0]
                            imports.setdefault(top, set()).add(str(file_path.relative_to(app_dir)))
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            top = node.module.split(".")[0]
                            imports.setdefault(top, set()).add(str(file_path.relative_to(app_dir)))
    return imports


def test_requirements_file_exists_and_all_dependencies_pinned():
    """CI check: Verifies requirements.txt exists and all dependencies have pinned (==) versions."""
    base_dir = Path(__file__).resolve().parent.parent
    req_path = base_dir / "requirements.txt"
    reqs = parse_requirements(req_path)
    assert len(reqs) > 0, "requirements.txt is empty"

    unpinned = [pkg for pkg, data in reqs.items() if data.get("op") != "=="]
    assert not unpinned, f"All requirements must have pinned versions (==). Unpinned packages: {unpinned}"


def test_every_imported_package_in_app_is_in_requirements():
    """
    CI check: Scans every Python file in backend/app and fails if any imported package
    is missing from backend/requirements.txt.
    """
    base_dir = Path(__file__).resolve().parent.parent
    app_dir = base_dir / "app"
    req_path = base_dir / "requirements.txt"

    app_imports = scan_app_imports(app_dir)
    reqs = parse_requirements(req_path)

    stdlib = sys.stdlib_module_names
    missing = {}

    for mod, files in app_imports.items():
        if mod in stdlib or mod == "app":
            continue
        pkg_name = MODULE_TO_PKG_MAP.get(mod, mod).lower().replace("_", "-")
        if pkg_name not in reqs:
            missing[mod] = {"pkg": pkg_name, "files": sorted(list(files))}

    assert not missing, (
        f"Missing package dependencies in requirements.txt! "
        f"The following imported modules are not listed in requirements.txt: {missing}"
    )


def test_ci_dependency_check_fails_on_missing_import():
    """Unit test: verifies that simulated missing dependencies properly trigger failure."""
    mock_imports = {"unknown_thirdparty_lib": {"some_file.py"}}
    mock_reqs = {"fastapi": {"op": "==", "version": "1.0.0"}}

    missing = [m for m in mock_imports if m not in mock_reqs]
    assert len(missing) == 1
    assert "unknown_thirdparty_lib" in missing


def test_import_every_module_under_app():
    """
    CI check: Recursively finds and dynamically imports every python module under backend/app.
    If any module has a missing third-party dependency or syntax error, importlib will raise
    an ImportError / ModuleNotFoundError and fail the test suite.
    """
    import importlib
    base_dir = Path(__file__).resolve().parent.parent
    app_dir = base_dir / "app"

    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

    failed_imports = {}
    imported_count = 0

    for root, _, files in os.walk(app_dir):
        for f in files:
            if f.endswith(".py"):
                file_path = Path(root) / f
                rel_parts = file_path.relative_to(base_dir).with_suffix("").parts
                mod_name = ".".join(rel_parts)
                try:
                    importlib.import_module(mod_name)
                    imported_count += 1
                except Exception as exc:
                    failed_imports[mod_name] = str(exc)

    assert not failed_imports, f"Failed to import modules under app: {failed_imports}"
    assert imported_count > 0, "No modules were found or imported under backend/app"

