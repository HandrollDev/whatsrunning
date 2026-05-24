"""Known process database for WhatsRunning.

As of v1.0.2, this module is a thin loader. All actual data (the curated
process descriptions, publisher purposes, suspicious-path patterns, etc.)
lives in `process_data.json` — the file the user can update via
Help -> Update process database without re-downloading the whole .exe.

Load order:
    1. %APPDATA%\\WhatsRunning\\process_data.json   (user-updated version, preferred)
    2. The bundled process_data.json next to this module / inside the .exe

Public names (kept stable so the rest of the app doesn't care about the
refactor):
    PROCESS_DB                  - dict[name -> entry]
    SYSTEM_PROCESS_NAMES        - set of system-process names
    SUSPICIOUS_PATH_FRAGMENTS   - list of suspicious path substrings
    SUSPICIOUS_CMDLINE_FRAGMENTS - list of suspicious cmdline substrings
    PUBLISHER_PURPOSE           - dict[publisher-substring -> purpose phrase]
    KNOWN_DEV_PARENTS           - set of parent process names that are dev tools
    DATA_VERSION                - ISO date string of the loaded JSON
    lookup(name)                - case-insensitive process lookup
    purpose_for(publisher)      - longest-match publisher purpose
    appdata_path()              - where the user-updateable JSON lives
    bundled_path()              - where the read-only default JSON lives
    reload()                    - force re-read from disk (used after update)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


WINDOWS = r"C:\Windows"
SYS32 = r"C:\Windows\System32"
SYSWOW = r"C:\Windows\SysWOW64"
PROGFILES = r"C:\Program Files"
PROGFILES86 = r"C:\Program Files (x86)"


def _resource_path(relative: str) -> str:
    """Path to a resource that ships with the app, works both when running
    from source AND when running from a PyInstaller onefile binary."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative)


def appdata_path() -> str:
    """Where the user-updateable JSON is stored on Windows."""
    base = os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming")
    return os.path.join(base, "WhatsRunning", "process_data.json")


def bundled_path() -> str:
    """The default JSON that ships with the .exe — read-only."""
    return _resource_path("process_data.json")


def _load_json() -> dict[str, Any]:
    """Returns the parsed JSON data. Tries AppData first (user updates),
    falls back to the bundled default."""
    # 1. User-updated copy in AppData
    p = appdata_path()
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass  # corrupt file -> fall back to bundled
    # 2. Bundled default
    b = bundled_path()
    if os.path.isfile(b):
        try:
            with open(b, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------- module state
PROCESS_DB: dict[str, dict[str, Any]] = {}
SYSTEM_PROCESS_NAMES: set[str] = set()
SUSPICIOUS_PATH_FRAGMENTS: list[str] = []
SUSPICIOUS_CMDLINE_FRAGMENTS: list[str] = []
PUBLISHER_PURPOSE: dict[str, str] = {}
KNOWN_DEV_PARENTS: set[str] = set()
DATA_VERSION: str = "unknown"


def reload() -> None:
    """Re-read data from disk. Called at module import and after the
    user clicks Help -> Update process database."""
    global PROCESS_DB, SYSTEM_PROCESS_NAMES, SUSPICIOUS_PATH_FRAGMENTS
    global SUSPICIOUS_CMDLINE_FRAGMENTS, PUBLISHER_PURPOSE, KNOWN_DEV_PARENTS
    global DATA_VERSION

    data = _load_json()
    PROCESS_DB = data.get("processes", {}) or {}
    SYSTEM_PROCESS_NAMES = set(data.get("system_process_names", []) or [])
    SUSPICIOUS_PATH_FRAGMENTS = list(data.get("suspicious_paths", []) or [])
    SUSPICIOUS_CMDLINE_FRAGMENTS = list(data.get("suspicious_cmdlines", []) or [])
    PUBLISHER_PURPOSE = data.get("publishers", {}) or {}
    KNOWN_DEV_PARENTS = set(data.get("known_dev_parents", []) or [])
    DATA_VERSION = data.get("version", "unknown")


# Load on import so the rest of the codebase sees populated state.
reload()


def lookup(name: str):
    """Look up a process by name (case-insensitive). Returns None if unknown."""
    if not name:
        return None
    return PROCESS_DB.get(name.lower())


def purpose_for(publisher: str) -> str:
    """Return a one-line 'what this publisher makes' hint, or '' if unknown.
    Matches publisher-name substrings case-insensitively; longest match wins."""
    if not publisher:
        return ""
    pub_lower = publisher.lower()
    matched_key = ""
    matched_value = ""
    for key, value in PUBLISHER_PURPOSE.items():
        if key in pub_lower and len(key) > len(matched_key):
            matched_key = key
            matched_value = value
    return matched_value
