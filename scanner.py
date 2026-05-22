"""Process scanner for WhatsRunning.

Enumerates running processes, collects metadata, and scores each one for risk
using a set of heuristics. Results are returned as a list of ProcessInfo dicts
that the UI can render directly.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from collections import Counter
from datetime import datetime
from typing import Any

import psutil

from process_database import (
    PROCESS_DB,
    SUSPICIOUS_CMDLINE_FRAGMENTS,
    SUSPICIOUS_PATH_FRAGMENTS,
    SYSTEM_PROCESS_NAMES,
    lookup,
)

try:
    import win32api  # type: ignore

    HAVE_WIN32 = True
except ImportError:
    HAVE_WIN32 = False


# Caches populated by collect(); keyed by absolute executable path.
_TRUST_CACHE: dict[str, bool | None] = {}
_SIGNER_CACHE: dict[str, str] = {}


def _batch_verify_signatures(paths: list[str]) -> None:
    """Verify many file signatures in one shot via PowerShell, populating
    _TRUST_CACHE and _SIGNER_CACHE in place.

    Get-AuthenticodeSignature is what Windows itself uses — it correctly
    handles embedded Authenticode AND catalog-signed binaries (which Microsoft
    Store apps and a lot of OS components rely on). We also pull the signer's
    X.500 Subject so callers can extract the publisher's legal name even when
    the binary's own version-info CompanyName field is empty (common for
    smaller OEMs and indie tools).

    Doing this as one PowerShell invocation rather than per-file keeps the
    scan fast even with several hundred unique exes.
    """
    unique = sorted({p for p in paths if p and os.path.isfile(p)})
    if not unique:
        return

    # IMPORTANT: do NOT add any `\r` or `\n` literals to this script. When
    # subprocess passes the whole script as a command-line argument, Windows /
    # PowerShell turns backslash-r / backslash-n into real CR/LF, which
    # breaks the script syntactically. Cert subjects effectively never contain
    # newline characters in practice, so we don't need to strip them.
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "while ($line = [Console]::In.ReadLine()) {"
        " if ([string]::IsNullOrWhiteSpace($line)) { continue }"
        " try { $s = Get-AuthenticodeSignature -LiteralPath $line }"
        " catch { Write-Output ('Error||' + $line); continue }"
        " $subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }"
        " Write-Output ($s.Status.ToString() + '|' + $subj + '|' + $line)"
        "}"
    )

    try:
        # CREATE_NO_WINDOW so PowerShell doesn't briefly flash a console window.
        creationflags = 0x08000000 if os.name == "nt" else 0
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            input="\n".join(unique),
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=creationflags,
        )
    except Exception:
        return

    for line in (proc.stdout or "").splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        status, subject, path = parts
        path = path.strip()
        _TRUST_CACHE[path] = status.strip() == "Valid"
        _SIGNER_CACHE[path] = _parse_signer_name(subject.strip())


def _parse_signer_name(subject: str) -> str:
    """Extract a human-readable signer name from an X.500 Subject DN string.

    Subjects look like:
        CN=GIGA-BYTE Technology Co., Ltd, O=GIGA-BYTE Technology Co., Ltd, L=Taipei, ...
        CN="Anthropic, PBC", O="Anthropic, PBC", L=San Francisco, ...

    We want the CN value — that's what humans recognise as the publisher.
    """
    if not subject or "CN=" not in subject:
        return ""
    start = subject.index("CN=") + 3
    rest = subject[start:]
    # Quoted CN value: take everything between the quotes.
    if rest.startswith('"'):
        end = rest.find('"', 1)
        return rest[1:end].strip() if end > 0 else rest[1:].strip()
    # Unquoted: ends at the next field marker (", O=", ", L=", etc.)
    for marker in (", O=", ", OU=", ", L=", ", S=", ", ST=", ", C=", ", E="):
        idx = rest.find(marker)
        if idx >= 0:
            return rest[:idx].strip()
    return rest.strip()


def _verify_trust(path: str) -> bool | None:
    """Per-process trust check. Reads the cache populated by collect()."""
    if not path:
        return None
    return _TRUST_CACHE.get(path)


def _signer_name(path: str) -> str:
    """Returns the certificate's CN (publisher name) for a given file path,
    or '' if not signed / not cached."""
    if not path:
        return ""
    return _SIGNER_CACHE.get(path, "")


# Risk levels — higher is worse.
RISK_TRUSTED = 0      # Known good, all signals clean
RISK_KNOWN = 1        # Recognized third-party app
RISK_UNKNOWN = 2      # Not in DB, but no red flags
RISK_LOW = 3          # One mild indicator
RISK_MEDIUM = 4       # Multiple mild indicators or one moderate
RISK_HIGH = 5         # Strong indicators of malicious behavior

RISK_LABELS = {
    RISK_TRUSTED: "Trusted",
    RISK_KNOWN: "Known",
    RISK_UNKNOWN: "Unknown",
    RISK_LOW: "Low Risk",
    RISK_MEDIUM: "Suspicious",
    RISK_HIGH: "High Risk",
}


# Dev tools and AI coding agents commonly spawn PowerShell with encoded
# commands as part of normal operation (running build steps, hooks, the agent's
# own tool calls). When the parent is one of these, treat -EncodedCommand as
# expected rather than as a malware indicator.
KNOWN_DEV_PARENTS = {
    "codex.exe", "claude.exe", "claude-code.exe", "cursor.exe",
    "code.exe", "devenv.exe", "msbuild.exe",
    "node.exe", "npm.exe", "yarn.exe", "pnpm.exe",
    "python.exe", "pythonw.exe", "py.exe",
    "go.exe", "cargo.exe", "rustc.exe",
    "docker.exe", "dockerd.exe", "podman.exe",
    "windowsterminal.exe",
    # WhatsRunning itself spawns PowerShell with -EncodedCommand for the
    # signature-verification batch. Without this, the scanner flags its own
    # PowerShell child as Suspicious every scan.
    "whatsrunning.exe",
}


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. Random-looking strings score ~3.5-4.5+."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_random(name: str) -> bool:
    """Heuristic for random-looking executable names — common in droppers."""
    stem = os.path.splitext(name)[0]
    if len(stem) < 6:
        return False
    entropy = _shannon_entropy(stem)
    # Mostly hex-looking, or high entropy + mixed case digits
    hex_like = bool(re.fullmatch(r"[a-f0-9]{8,}", stem.lower())) and any(c.isdigit() for c in stem)
    high_entropy = entropy > 3.6 and sum(c.isdigit() for c in stem) >= 3
    return hex_like or high_entropy


def _path_in_suspicious_folder(path: str) -> str | None:
    """Returns the matched fragment if the path lives somewhere suspicious."""
    if not path:
        return None
    p = path.lower().replace("/", "\\")
    for frag in SUSPICIOUS_PATH_FRAGMENTS:
        if frag in p:
            return frag
    return None


def _cmdline_suspicious(cmdline: str) -> list[str]:
    """Returns the list of suspicious fragments seen in the command line."""
    if not cmdline:
        return []
    cl = cmdline.lower()
    return [f.strip() for f in SUSPICIOUS_CMDLINE_FRAGMENTS if f in cl]


def _get_version_info(path: str) -> dict[str, str]:
    """Best-effort: read CompanyName / ProductName / FileDescription from PE resources."""
    if not (HAVE_WIN32 and path and os.path.isfile(path)):
        return {}
    try:
        info = win32api.GetFileVersionInfo(path, "\\")
        lang, codepage = win32api.GetFileVersionInfo(path, r"\VarFileInfo\Translation")[0]
        prefix = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\"
        out: dict[str, str] = {}
        for key in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename"):
            try:
                val = win32api.GetFileVersionInfo(path, prefix + key)
                if val:
                    out[key] = val.strip()
            except Exception:
                pass
        return out
    except Exception:
        return {}


def _path_matches_expected(path: str, expected: list[str]) -> bool:
    if not path or not expected:
        return False
    p = path.lower().replace("/", "\\")
    for exp in expected:
        if exp.lower().replace("/", "\\") in p:
            return True
    return False


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _format_age(start_epoch: float) -> str:
    try:
        delta = datetime.now() - datetime.fromtimestamp(start_epoch)
        total = int(delta.total_seconds())
        if total < 60:
            return f"{total}s"
        if total < 3600:
            return f"{total // 60}m"
        if total < 86400:
            return f"{total // 3600}h {(total % 3600) // 60}m"
        return f"{total // 86400}d {(total % 86400) // 3600}h"
    except Exception:
        return "—"


def assess(proc_data: dict[str, Any]) -> dict[str, Any]:
    """Run heuristics on a single process and produce the final risk assessment."""
    name = (proc_data.get("name") or "").lower()
    exe = proc_data.get("exe") or ""
    cmdline = proc_data.get("cmdline") or ""
    parent_name = (proc_data.get("parent_name") or "").lower()

    db_entry = lookup(name)
    indicators: list[str] = []
    positives: list[str] = []
    risk = RISK_UNKNOWN

    # System-name impersonation — strongest signal we have.
    if name in SYSTEM_PROCESS_NAMES and exe:
        expected = (db_entry or {}).get("expected_paths") or []
        if expected and not _path_matches_expected(exe, expected):
            indicators.append(
                f"Uses a Windows system process name ({name}) but runs from {exe} — "
                f"genuine {name} only runs from {expected[0]}."
            )
            risk = RISK_HIGH

    # Suspicious folder — but mild on its own.
    sus_folder = _path_in_suspicious_folder(exe)
    if sus_folder:
        indicators.append(f"Executable lives in {sus_folder.strip(chr(92))} — unusual location.")
        risk = max(risk, RISK_LOW)

    # Suspicious command line. Demote when the parent is a known dev tool — IDEs,
    # AI coding agents, and build tools routinely spawn PowerShell with encoded
    # commands as a normal part of operation. Without this demotion the scanner
    # would flag its own host process.
    cmd_hits = _cmdline_suspicious(cmdline)
    if cmd_hits:
        if parent_name in KNOWN_DEV_PARENTS:
            positives.append(
                f"Uses '{cmd_hits[0]}', but launched by {parent_name} — common for dev tools."
            )
        else:
            for h in cmd_hits:
                indicators.append(f"Command line contains '{h}' — often seen in malware loaders.")
            risk = max(risk, RISK_MEDIUM if len(cmd_hits) == 1 else RISK_HIGH)

    # Random / hex-looking name — mild.
    if name and _looks_random(name):
        indicators.append(f"Executable name '{name}' looks randomly generated.")
        risk = max(risk, RISK_LOW)

    # Read version info + verify trust. We always do this when we have a path —
    # WinVerifyTrust is cached per-path so the cost is paid once per executable.
    version_info: dict[str, str] = {}
    signed: bool | None = None
    signer: str = ""
    if exe:
        version_info = _get_version_info(exe)
        signed = _verify_trust(exe)
        signer = _signer_name(exe)
        if signed is False:
            # Don't surface "unsigned" as an indicator for known-trusted Microsoft
            # binaries — that's just our check disagreeing with the DB, not a
            # real risk signal.
            if not (db_entry and db_entry.get("trust") == "trusted"):
                indicators.append("Executable is not digitally signed or trusted by Windows.")
                if not db_entry:
                    risk = max(risk, RISK_LOW)
        elif signed is True:
            positives.append("Trusted by Windows (signature verified).")

    company = version_info.get("CompanyName", "")

    # Final categorization — known-good wins unless we found a strong red flag.
    if db_entry and risk < RISK_MEDIUM:
        expected = db_entry.get("expected_paths") or []
        path_ok = (not expected) or _path_matches_expected(exe, expected) or not exe
        if path_ok:
            risk = RISK_TRUSTED if db_entry["trust"] == "trusted" else RISK_KNOWN
            positives.append(f"Recognised as {db_entry['publisher']} software.")
        else:
            indicators.append(
                f"Known process name but lives at {exe} instead of {expected[0]}."
            )
            risk = max(risk, RISK_MEDIUM)

    # Signed by Microsoft is a strong positive even for unknowns.
    if (
        not db_entry
        and signed
        and company
        and ("microsoft" in company.lower())
        and risk <= RISK_UNKNOWN
    ):
        positives.append("Signed by Microsoft.")
        risk = RISK_TRUSTED

    # Signed by some other vendor: bump unknowns down to known.
    if not db_entry and signed and company and risk == RISK_UNKNOWN:
        positives.append(f"Signed by {company}.")
        risk = RISK_KNOWN

    return {
        "risk": risk,
        "risk_label": RISK_LABELS[risk],
        "indicators": indicators,
        "positives": positives,
        "db_entry": db_entry,
        "version_info": version_info,
        "signed": signed,
        "company": company,
        "signer": signer,
    }


def collect() -> list[dict[str, Any]]:
    """Enumerate every running process and assess it. Returns a list of dicts."""
    # Prime CPU sampling: psutil returns 0% on the first call unless we ask twice.
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Build pid -> name map up front so we can resolve parent names during assess().
    pid_to_name: dict[int, str] = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            pid_to_name[p.info["pid"]] = p.info.get("name") or ""
        except Exception:
            pass

    results: list[dict[str, Any]] = []

    for proc in psutil.process_iter(["pid", "name", "username", "create_time", "ppid"]):
        info = proc.info
        pid = info["pid"]
        name = info.get("name") or ""
        record: dict[str, Any] = {
            "pid": pid,
            "name": name,
            "username": info.get("username") or "",
            "create_time": info.get("create_time"),
            "ppid": info.get("ppid"),
            "exe": "",
            "cmdline": "",
            "memory": 0,
            "memory_str": "0 B",
            "cpu": 0.0,
            "num_threads": 0,
            "connections": 0,
            "age_str": "—",
            "access_limited": False,
        }

        try:
            record["exe"] = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            record["access_limited"] = True
        except Exception:
            pass

        try:
            cl = proc.cmdline()
            record["cmdline"] = " ".join(cl) if cl else ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            record["access_limited"] = True
        except Exception:
            pass

        try:
            mem = proc.memory_info().rss
            record["memory"] = mem
            record["memory_str"] = _format_bytes(mem)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            record["cpu"] = proc.cpu_percent(interval=None)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            record["num_threads"] = proc.num_threads()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            record["connections"] = len(proc.net_connections(kind="inet"))
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
            pass
        except Exception:
            pass

        if record["create_time"]:
            record["age_str"] = _format_age(record["create_time"])

        record["parent_name"] = pid_to_name.get(record["ppid"], "")
        results.append(record)

    # Batch-verify all unique exe paths in one PowerShell call. Doing this
    # upfront (rather than per-process inside assess) means we pay the PS
    # startup cost exactly once. Populates both _TRUST_CACHE and _SIGNER_CACHE.
    unique_paths = list({r["exe"] for r in results if r["exe"]})
    _batch_verify_signatures(unique_paths)

    # Now run heuristics — _verify_trust will hit the warm cache.
    for r in results:
        r["assessment"] = assess(r)

    # Sort: highest risk first, then largest memory.
    results.sort(key=lambda r: (-r["assessment"]["risk"], -r["memory"]))
    return results


def summary(results: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate counts for the stat cards at the top of the UI."""
    out = {label: 0 for label in RISK_LABELS.values()}
    out["Total"] = len(results)
    for r in results:
        out[r["assessment"]["risk_label"]] += 1
    return out
