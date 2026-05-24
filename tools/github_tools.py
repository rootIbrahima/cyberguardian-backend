import base64
import json
import re
import shutil
import subprocess  # nosec B404 — subprocess required for git/bandit/npm invocations
import sys
import tempfile
from pathlib import Path

import httpx

# ── Secret patterns for TruffleHog-style detection ────────────────────────────
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                                        'AWS Access Key'),
    (r'sk-[a-zA-Z0-9]{32,}',                                                     'OpenAI API Key'),
    (r'ghp_[a-zA-Z0-9]{36}',                                                     'GitHub Personal Token'),
    (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',                        'Slack Bot Token'),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                  'Google API Key'),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',                           'Private Key'),
    (r'(?<![a-zA-Z0-9_])password\s*=\s*["\'][^"\']{8,}["\']',                  'Hardcoded Password'),
    (r'(?<![a-zA-Z0-9_])(?:secret_key|api_key|apikey|access_token)\s*=\s*["\'][^"\']{8,}["\']',
                                                                                  'Hardcoded Secret/Token'),
]

_GH_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "CyberGuardian-EASM/1.0"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_github_url(url: str):
    """Returns (owner, repo) or None."""
    m = re.search(
        r'github\.com[:/]([^/\s]+)/([^/\s\.]+?)(?:\.git)?(?:[/?#].*)?$',
        url, re.IGNORECASE,
    )
    return (m.group(1), m.group(2)) if m else None


def _detect_language_from_files(tmpdir: str) -> str:
    """Infer primary language from repo structure when GitHub API returns null."""
    root = Path(tmpdir)
    if (root / "package.json").exists():
        return "TypeScript" if any(root.rglob("*.ts")) else "JavaScript"
    if any([
        (root / "requirements.txt").exists(),
        (root / "setup.py").exists(),
        (root / "pyproject.toml").exists(),
        bool(list(root.glob("*.py"))),
    ]):
        return "Python"
    if (root / "go.mod").exists():
        return "Go"
    if (root / "Cargo.toml").exists():
        return "Rust"
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        return "Java"
    return ""


def _clone(owner: str, repo: str) -> tuple[str | None, str | None]:
    """Shallow-clone repo into a temp dir. Returns (tmpdir, error)."""
    tmpdir = tempfile.mkdtemp(prefix="cg_gh_")
    try:
        r = subprocess.run(  # nosec B603 B607 — list args (no shell=True), owner/repo validated by regex
            ["git", "clone", "--depth", "1", "--quiet",
             f"https://github.com/{owner}/{repo}.git", tmpdir],
            capture_output=True, text=True, timeout=90,
        )
        if r.returncode == 0:
            return tmpdir, None
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, r.stderr.strip()[:250]
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, "Timeout : dépôt trop volumineux"
    except FileNotFoundError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, "git n'est pas installé sur le serveur"


# ── Tool 1 : github_info ──────────────────────────────────────────────────────

def github_info(target: str) -> dict:
    """Fetch repository metadata from GitHub REST API v3."""
    parsed = _parse_github_url(target)
    if not parsed:
        return {"error": f"URL GitHub invalide : {target}"}
    owner, repo = parsed

    try:
        resp = httpx.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=_GH_HEADERS, timeout=10,
        )
        if resp.status_code == 404:
            return {"error": "Dépôt introuvable ou privé"}
        resp.raise_for_status()
        d = resp.json()

        branches_count    = 0
        contributors_count = 0
        try:
            br = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/branches",
                headers=_GH_HEADERS, params={"per_page": 100}, timeout=10,
            )
            if br.status_code == 200:
                branches_count = len(br.json())
        except Exception:  # nosec B110 — optional metadata, skip on any API failure
            pass
        try:
            co = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/contributors",
                headers=_GH_HEADERS, params={"per_page": 100}, timeout=10,
            )
            if co.status_code == 200:
                contributors_count = len(co.json())
        except Exception:  # nosec B110 — optional metadata, skip on any API failure
            pass

        return {
            "owner":        owner,
            "repo":         repo,
            "full_name":    d.get("full_name", f"{owner}/{repo}"),
            "description":  d.get("description") or "",
            "private":      d.get("private", False),
            "visibility":   "Privé" if d.get("private") else "Public",
            "stars":        d.get("stargazers_count", 0),
            "forks":        d.get("forks_count", 0),
            "open_issues":  d.get("open_issues_count", 0),
            "default_branch": d.get("default_branch", "main"),
            "branches":     branches_count,
            "contributors": contributors_count,
            "language":     d.get("language") or "N/A",
            "created_at":   (d.get("created_at") or "")[:10],
            "updated_at":   (d.get("updated_at") or "")[:10],
            "size_kb":      d.get("size", 0),
            "license":      (d.get("license") or {}).get("spdx_id") or "Aucune",
            "archived":     d.get("archived", False),
            "topics":       d.get("topics", []),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Tool 2 : scan_bandit ──────────────────────────────────────────────────────

def _run_bandit(tmpdir: str) -> dict:
    """Run Bandit on an already-cloned directory."""
    try:
        result = subprocess.run(  # nosec B603 — sys.executable is trusted, list args, no shell=True
            [sys.executable, "-m", "bandit", "-r", tmpdir, "-f", "json", "-q", "--exit-zero"],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(result.stdout)
        findings = []
        for item in data.get("results", []):
            try:
                file_rel = str(Path(item["filename"]).relative_to(tmpdir)).replace("\\", "/")
            except Exception:
                file_rel = item.get("filename", "")
            findings.append({
                "severity":   item.get("issue_severity", "LOW"),
                "confidence": item.get("issue_confidence", "LOW"),
                "file":       file_rel,
                "line":       item.get("line_number", 0),
                "issue":      item.get("issue_text", ""),
                "cwe":        f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else "",
                "code":       (item.get("code") or "").strip()[:120],
            })
        totals = data.get("metrics", {}).get("_totals", {})
        return {"findings": findings, "loc": totals.get("loc", 0)}
    except json.JSONDecodeError:
        return {"findings": [], "error": "Bandit : sortie JSON invalide"}
    except FileNotFoundError:
        return {"findings": [], "error": "Bandit n'est pas installé (pip install bandit)"}
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "Timeout bandit"}


# ── Tool 3 : scan_safety ──────────────────────────────────────────────────────

def scan_safety(target: str) -> dict:
    """Check requirements.txt against OSV.dev vulnerability database."""
    parsed = _parse_github_url(target)
    if not parsed:
        return {"findings": [], "error": "URL GitHub invalide"}
    owner, repo = parsed

    req_files = [
        "requirements.txt",
        "requirements/base.txt",
        "requirements/prod.txt",
        "requirements/common.txt",
    ]
    packages   = []
    found_file = None

    for req_file in req_files:
        try:
            resp = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{req_file}",
                headers=_GH_HEADERS, timeout=10,
            )
            if resp.status_code != 200:
                continue
            content    = base64.b64decode(resp.json()["content"]).decode("utf-8", errors="ignore")
            found_file = req_file
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", "git+")):
                    continue
                m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[>=<~!]+\s*([0-9][^\s,;#]*)', line)
                if m:
                    packages.append({"name": m.group(1).lower(), "version": m.group(2).strip()})
            break
        except Exception:  # nosec B112 — skip req file variant on network/decode error
            continue

    if not packages:
        return {
            "findings":         [],
            "packages_checked": 0,
            "requirements_file": found_file,
            "note": "Aucun fichier requirements.txt trouvé ou aucune dépendance parsée",
        }

    findings = []
    for pkg in packages:
        try:
            osv = httpx.post(
                "https://api.osv.dev/v1/query",
                json={
                    "version": pkg["version"],
                    "package": {"name": pkg["name"], "ecosystem": "PyPI"},
                },
                timeout=10,
            )
            if osv.status_code != 200:
                continue
            for v in osv.json().get("vulns", [])[:3]:
                aliases = v.get("aliases", [])
                cve_id  = next((a for a in aliases if a.startswith("CVE-")), v.get("id", "N/A"))
                severity = (v.get("database_specific") or {}).get("severity", "HIGH").upper()
                findings.append({
                    "package":  pkg["name"],
                    "version":  pkg["version"],
                    "cve":      cve_id,
                    "severity": severity,
                    "desc":     v.get("summary", "")[:150],
                })
        except Exception:  # nosec B112 — skip package on OSV API error, continue others
            continue

    return {
        "findings":         findings,
        "packages_checked": len(packages),
        "requirements_file": found_file,
    }


# ── Tool 4 : scan_trufflehog ──────────────────────────────────────────────────

def _run_trufflehog(tmpdir: str) -> dict:
    """Scan cloned directory for secrets using regex patterns."""
    SKIP_EXT  = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".zip", ".pdf", ".pyc", ".bin", ".exe", ".dll", ".so",
    }
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__",
        ".venv", "venv", "env", "dist", "build", ".next",
    }

    findings = []
    for filepath in Path(tmpdir).rglob("*"):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() in SKIP_EXT:
            continue
        if any(d in filepath.parts for d in SKIP_DIRS):
            continue
        try:
            content  = filepath.read_text(encoding="utf-8", errors="ignore")
            file_rel = filepath.relative_to(tmpdir).as_posix()
            for pattern, secret_type in SECRET_PATTERNS:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[: m.start()].count("\n") + 1
                    val      = m.group(0)
                    masked   = val[:8] + "***" + val[-4:] if len(val) > 14 else val[:4] + "***"
                    findings.append({
                        "type":     secret_type,
                        "file":     file_rel,
                        "line":     line_num,
                        "value":    masked,
                        "verified": False,
                    })
                    if len(findings) >= 20:
                        break
                if len(findings) >= 20:
                    break
            if len(findings) >= 20:
                break
        except Exception:  # nosec B112 — skip unreadable file (binary, permissions), continue scan
            continue

    return {"findings": findings}


# ── Tool 5 : npm audit ───────────────────────────────────────────────────────

def _run_npm_audit(tmpdir: str) -> dict:
    """Run npm audit on an already-cloned JS/TS repository."""
    try:
        # Generate package-lock.json without downloading node_modules
        subprocess.run(  # nosec B603 B607 — list args, no shell=True, cwd is a controlled tmpdir
            ["npm", "install", "--package-lock-only", "--ignore-scripts"],
            cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result = subprocess.run(  # nosec B603 B607 — list args, no shell=True, cwd is a controlled tmpdir
            ["npm", "audit", "--json"],
            cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        # npm audit exits non-zero when vulnerabilities found — parse stdout anyway
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"findings": [], "error": "npm audit : sortie JSON invalide"}

        findings = []

        # npm v7+ format
        if "vulnerabilities" in data:
            for pkg_name, vuln in data["vulnerabilities"].items():
                sev  = vuln.get("severity", "low")
                desc = ""
                for via in vuln.get("via", []):
                    if isinstance(via, dict):
                        desc = via.get("title", "")
                        break
                findings.append({
                    "package":  pkg_name,
                    "severity": sev,
                    "issue":    desc or f"Vulnérabilité {sev}",
                    "range":    vuln.get("range", ""),
                    "fix":      vuln.get("fixAvailable", False),
                })

        # npm v6 format
        elif "advisories" in data:
            for adv in data["advisories"].values():
                findings.append({
                    "package":  adv.get("module_name", ""),
                    "severity": adv.get("severity", "low"),
                    "issue":    adv.get("title", ""),
                    "range":    adv.get("vulnerable_versions", ""),
                    "fix":      bool(adv.get("patched_versions")),
                })

        meta = data.get("metadata", {}).get("vulnerabilities", {})
        return {
            "findings": findings,
            "summary": {
                "critical": meta.get("critical", 0),
                "high":     meta.get("high", 0),
                "moderate": meta.get("moderate", 0),
                "low":      meta.get("low", 0),
            },
        }

    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "Timeout npm audit"}
    except FileNotFoundError:
        return {"findings": [], "error": "npm n'est pas installé sur le serveur"}
    except Exception as e:
        return {"findings": [], "error": str(e)}


# ── Combined scan ─────────────────────────────────────────────────────────────

def scan_github(target: str) -> dict:
    """Run GitHub tools (language-aware) and return combined results + score /30."""
    parsed = _parse_github_url(target)
    if not parsed:
        return {"error": "URL GitHub invalide"}

    owner, repo = parsed
    info = github_info(target)

    # Language: GitHub API first, strip "N/A", then fallback to file-structure detection
    api_lang = info.get("language") or ""
    if api_lang == "N/A":
        api_lang = ""

    # Clone once — needed for all file-based tools + language fallback
    tmpdir, clone_err = _clone(owner, repo)

    language  = api_lang or (_detect_language_from_files(tmpdir) if tmpdir else "")
    lang_low  = language.lower()
    is_python = lang_low == "python"
    is_js_ts  = lang_low in ("javascript", "typescript")

    # Safety uses GitHub API — no clone needed
    if is_python:
        safety = scan_safety(target)
    else:
        safety = {
            "findings":          [],
            "packages_checked":  0,
            "note":              f"N/A — {language or 'langage non détecté'}",
        }

    if tmpdir:
        bandit     = _run_bandit(tmpdir) if is_python else {
            "findings": [],
            "note":     f"N/A — {language or 'langage non détecté'}",
        }
        npm_audit  = _run_npm_audit(tmpdir) if is_js_ts else None
        trufflehog = _run_trufflehog(tmpdir)
        shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        err_obj   = {"findings": [], "error": clone_err or "Clonage impossible"}
        bandit    = ({**err_obj, "loc": 0} if is_python
                     else {"findings": [], "note": f"N/A — {language or 'langage non détecté'}"})
        npm_audit  = dict(err_obj) if is_js_ts else None
        trufflehog = dict(err_obj)

    # Score /30
    score = 30

    if is_python:
        for f in bandit.get("findings", []):
            sev = f.get("severity", "LOW")
            score -= 5 if sev == "HIGH" else 2 if sev == "MEDIUM" else 1
        for f in safety.get("findings", []):
            sev = f.get("severity", "HIGH")
            score -= 8 if sev == "CRITICAL" else 5 if sev == "HIGH" else 2 if sev == "MEDIUM" else 1

    elif is_js_ts and npm_audit:
        for f in npm_audit.get("findings", []):
            sev = f.get("severity", "low").lower()
            score -= 8 if sev == "critical" else 5 if sev == "high" else 2 if sev == "moderate" else 1

    for _ in trufflehog.get("findings", []):
        score -= 10

    return {
        "github_info": info,
        "bandit":      bandit,
        "safety":      safety,
        "trufflehog":  trufflehog,
        "npm_audit":   npm_audit,
        "langage":     language if language else "N/A",
        "score":       max(0, min(30, score)),
        "max":         30,
    }
