"""
dependency_analysis/dep_scanner.py
Parses dependency files and queries OSV.dev for known CVEs.
Also detects potential typosquatting against popular packages.
No code execution — purely file parsing and API queries.
"""

import os
import re
import json
import urllib.request
from typing import List, Dict

OSV_API = "https://api.osv.dev/v1/query"

# Well-known packages used for typosquatting similarity checks
KNOWN_PACKAGES = [
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "matplotlib", "tensorflow", "torch", "sklearn", "scikit-learn",
    "sqlalchemy", "celery", "redis", "boto3", "paramiko", "cryptography",
    "pillow", "pyyaml", "click", "fastapi", "uvicorn", "aiohttp",
    "httpx", "pytest", "black", "mypy", "setuptools", "pip", "wheel",
    "twine", "poetry", "pydantic", "alembic", "stripe", "psycopg2",
]

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "env"}


# ── Typosquatting ─────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _is_typosquat(pkg: str) -> str | None:
    """
    Returns the name of the package being spoofed if suspicious,
    otherwise None.
    """
    cleaned = pkg.lower().replace("-", "").replace("_", "")
    for known in KNOWN_PACKAGES:
        k = known.lower().replace("-", "").replace("_", "")
        if cleaned == k:
            return None  # exact match — legitimate
        if _levenshtein(cleaned, k) <= 2:
            return known
    return None


# ── File parsers ──────────────────────────────────────────────

def _parse_requirements_txt(path: str) -> List[str]:
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "-", ".")):
                    continue
                pkg = re.split(r"[>=<!;\[@]", line)[0].strip()
                if pkg:
                    pkgs.append(pkg)
    except Exception:
        pass
    return pkgs


def _parse_setup_py(path: str) -> List[str]:
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        for match in re.findall(
            r"install_requires\s*=\s*\[([^\]]+)\]", content, re.DOTALL
        ):
            for item in re.findall(r"['\"]([^'\"]+)['\"]", match):
                pkg = re.split(r"[>=<!;\[@]", item)[0].strip()
                if pkg:
                    pkgs.append(pkg)
    except Exception:
        pass
    return pkgs


def _parse_pyproject_toml(path: str) -> List[str]:
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        for match in re.findall(
            r"dependencies\s*=\s*\[([^\]]+)\]", content, re.DOTALL
        ):
            for item in re.findall(r"['\"]([^'\"]+)['\"]", match):
                pkg = re.split(r"[>=<!;\[@ ]", item)[0].strip()
                if pkg and not pkg.lower().startswith("python"):
                    pkgs.append(pkg)
    except Exception:
        pass
    return pkgs


def _parse_package_json(path: str) -> List[str]:
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            pkgs.extend(data.get(section, {}).keys())
    except Exception:
        pass
    return pkgs


# ── OSV.dev query ─────────────────────────────────────────────

def _query_osv(package: str, ecosystem: str) -> List[Dict]:
    """Query OSV.dev for known vulnerabilities. Returns list of vulns."""
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem}
    }).encode()
    try:
        req = urllib.request.Request(
            OSV_API,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()).get("vulns", [])
    except Exception:
        return []


# ── Main scanner ──────────────────────────────────────────────

def scan_dependencies(repo_path: str) -> Dict:
    """
    Find all dependency files in repo_path, parse them,
    check for CVEs and typosquatting.
    Returns structured findings dict.
    """
    parsers = {
        "requirements.txt": ("PyPI", _parse_requirements_txt),
        "setup.py":         ("PyPI", _parse_setup_py),
        "pyproject.toml":   ("PyPI", _parse_pyproject_toml),
        "package.json":     ("npm",  _parse_package_json),
    }

    dep_files_found = []
    raw_packages = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname, (ecosystem, parser) in parsers.items():
            if fname in files:
                fpath = os.path.join(root, fname)
                dep_files_found.append(fpath)
                for pkg in parser(fpath):
                    raw_packages.append({
                        "name":        pkg,
                        "ecosystem":   ecosystem,
                        "source_file": fname,
                    })

    # Deduplicate by (name, ecosystem)
    seen = set()
    packages = []
    for p in raw_packages:
        key = (p["name"].lower(), p["ecosystem"])
        if key not in seen:
            seen.add(key)
            packages.append(p)

    # Analyse each package
    flagged = []
    total_cves = 0

    for pkg in packages:
        result = {
            "package":           pkg["name"],
            "ecosystem":         pkg["ecosystem"],
            "source_file":       pkg["source_file"],
            "cves":              [],
            "typosquat_target":  None,
            "flags":             [],
        }

        # Typosquatting check (PyPI only)
        if pkg["ecosystem"] == "PyPI":
            spoof_target = _is_typosquat(pkg["name"])
            if spoof_target:
                result["typosquat_target"] = spoof_target
                result["flags"].append(
                    f"Name '{pkg['name']}' closely resembles "
                    f"'{spoof_target}' — possible typosquatting."
                )

        # CVE lookup
        vulns = _query_osv(pkg["name"], pkg["ecosystem"])
        if vulns:
            total_cves += len(vulns)
            for v in vulns[:5]:  # cap at 5 per package
                result["cves"].append({
                    "id":       v.get("id", "UNKNOWN"),
                    "summary":  (v.get("summary") or "No summary.")[:200],
                    "severity": v.get("database_specific", {}).get(
                        "severity", "UNKNOWN"
                    ),
                })

        if result["cves"] or result["flags"]:
            flagged.append(result)

    # Dependency risk score (0–100)
    dep_risk = 0
    dep_risk += min(total_cves * 8, 60)
    dep_risk += min(
        sum(10 for f in flagged if f["typosquat_target"]), 30
    )
    dep_risk += min(
        sum(5 for f in flagged for _ in f["flags"]), 20
    )
    dep_risk = min(dep_risk, 100)

    print(
        f"[deps] Packages analysed: {len(packages)}. "
        f"Flagged: {len(flagged)}. CVEs: {total_cves}. "
        f"Dep risk score: {dep_risk}"
    )

    return {
        "dep_files_found":   dep_files_found,
        "packages_analysed": len(packages),
        "flagged_packages":  flagged,
        "total_cves":        total_cves,
        "dep_risk_score":    dep_risk,
    }
