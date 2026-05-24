"""WhatsRunning — a Windows process inspector with a focus on flagging the suspicious.

Launch with `python whatsrunning.py` (or the bundled run.bat). The scan is one-shot:
nothing happens until the Scan button is clicked.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
import traceback
import urllib.parse
from datetime import datetime
from typing import Any

from PySide6.QtCore import (
    QEvent,
    QObject,
    QSharedMemory,
    QSize,
    Qt,
    QThread,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QIcon,
    QPainter,
    QPalette,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import psutil

import scanner
from process_database import purpose_for


# ---------------------------------------------------------------- branding
# Edit these in one place — every UI surface (window title, header, About
# dialog, status bar) reads from here, so renaming the product is a one-line
# change.
APP_NAME = "WhatsRunning"
TAGLINE = "Task Manager, but it tells you what everything is."
VERSION = "1.0.2"
AUTHOR = "Handroll"
COPYRIGHT_YEAR = datetime.now().year
DONATION_URL = "https://ko-fi.com/handroll"           # 0% platform fee on one-time tips
WEBSITE_URL = "https://whatsrunning.app"              # planned domain — reserve via Cloudflare Registrar
GITHUB_REPO_URL = "https://github.com/HandrollDev/whatsrunning"
# Derived: the GitHub API endpoint we query when the user clicks
# "Help → Check for updates…". Recomputed from GITHUB_REPO_URL so renaming the
# repo is a one-line change.
_REPO_PATH = GITHUB_REPO_URL.rstrip("/").removeprefix("https://github.com/")
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{_REPO_PATH}/releases/latest"
GITHUB_RELEASES_PAGE = f"{GITHUB_REPO_URL}/releases"
# Raw URL of the curated process database JSON. Fetched on demand when the
# user clicks Help → Update process database…
DATABASE_URL = f"https://raw.githubusercontent.com/{_REPO_PATH}/main/process_data.json"


# ---------------------------------------------------------------- color tokens
BG = "#0d1117"
SURFACE = "#161b22"
SURFACE_HI = "#1c232c"
BORDER = "#30363d"
BORDER_HI = "#3d444d"
TEXT = "#e6edf3"
TEXT_DIM = "#7d8590"
TEXT_FAINT = "#484f58"
ACCENT = "#2f81f7"
ACCENT_HOVER = "#388bfd"

RISK_COLORS = {
    "Trusted":    "#3fb950",
    "Known":      "#58a6ff",
    "Unknown":    "#8b949e",
    "Low Risk":   "#d29922",
    "Suspicious": "#f0883e",
    "High Risk":  "#f85149",
}

CATEGORY_COLORS = {
    "Windows Core": "#58a6ff",
    "Security":     "#f85149",
    "Browser":      "#f0883e",
    "Communication":"#bc8cff",
    "Gaming":       "#3fb950",
    "Media":        "#ff7eb6",
    "Productivity": "#33b1ff",
    "Developer":    "#d29922",
    "Shell":        "#7d8590",
    "Drivers":      "#39c5cf",
    "Utility":      "#8b949e",
    "Unknown":      "#484f58",
}


# ---------------------------------------------------------------- stylesheet
STYLESHEET = f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
    font-size: 13px;
}}

QMainWindow {{
    background: {BG};
}}

#Header {{
    background: {BG};
    border-bottom: 1px solid {BORDER};
}}

#AppName {{
    font-size: 19px;
    font-weight: 600;
    letter-spacing: 0.2px;
}}

#AppSub {{
    color: {TEXT_DIM};
    font-size: 12px;
}}

#StatusText {{
    color: {TEXT_DIM};
    font-size: 12px;
}}

#StatCard {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}

#StatCard:hover {{
    border-color: {ACCENT};
    background: {SURFACE_HI};
}}

#StatusText:hover {{
    color: {TEXT};
    text-decoration: underline;
}}

#StatLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

#StatValue {{
    color: {TEXT};
    font-size: 26px;
    font-weight: 600;
}}

#ScanButton {{
    background: {ACCENT};
    color: white;
    border: 0;
    border-radius: 6px;
    padding: 10px 22px;
    font-weight: 600;
    font-size: 13px;
}}

#ScanButton:hover {{
    background: {ACCENT_HOVER};
}}

#ScanButton:disabled {{
    background: #21262d;
    color: {TEXT_FAINT};
}}

QMenuBar {{
    background: {BG};
    color: {TEXT};
    border-bottom: 1px solid {BORDER};
    padding: 2px 4px;
}}

QMenuBar::item {{
    background: transparent;
    padding: 6px 10px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background: {SURFACE_HI};
}}

QMenu {{
    background: {SURFACE};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background: {SURFACE_HI};
    color: {TEXT};
}}

QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 4px 8px;
}}

#AboutDialog {{
    background: {BG};
}}

#AboutTitle {{
    font-size: 26px;
    font-weight: 700;
    color: {TEXT};
}}

#AboutTagline {{
    color: {TEXT_DIM};
    font-size: 13px;
}}

#AboutBody {{
    color: {TEXT};
    font-size: 12px;
    line-height: 1.5;
}}

#AboutVersion {{
    color: {TEXT_DIM};
    font-size: 11px;
}}

#LinkButton {{
    background: {SURFACE};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 500;
}}

#LinkButton:hover {{
    background: {SURFACE_HI};
    border-color: {BORDER_HI};
}}

#PrimaryLinkButton {{
    background: {ACCENT};
    color: white;
    border: 0;
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 600;
}}

#PrimaryLinkButton:hover {{
    background: {ACCENT_HOVER};
}}

#ActionButton {{
    background: {SURFACE_HI};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 12px;
    font-weight: 500;
}}

#ActionButton:hover {{
    background: {BG};
    border-color: {ACCENT};
    color: {ACCENT};
}}

#ActionButton:disabled {{
    background: transparent;
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}

#DangerButton {{
    background: {SURFACE_HI};
    color: #f85149;
    border: 1px solid #f8514955;
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 12px;
    font-weight: 600;
}}

#DangerButton:hover {{
    background: #f85149;
    color: white;
    border-color: #f85149;
}}

#DangerButton:disabled {{
    background: transparent;
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}

QComboBox, QLineEdit {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    color: {TEXT};
    selection-background-color: {ACCENT};
}}

QComboBox:hover, QLineEdit:hover {{
    border-color: {BORDER_HI};
}}

QComboBox::drop-down {{ border: 0; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    outline: 0;
    padding: 4px;
}}

QTableWidget {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: transparent;
    outline: 0;
    selection-background-color: {SURFACE_HI};
    selection-color: {TEXT};
}}

QTableWidget::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT};
}}

QTableWidget::item:selected {{
    background: {SURFACE_HI};
    color: {TEXT};
}}

QHeaderView::section {{
    background: {SURFACE};
    color: {TEXT_DIM};
    border: 0;
    border-bottom: 1px solid {BORDER};
    padding: 8px 8px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QTableCornerButton::section {{
    background: {SURFACE};
    border: 0;
    border-bottom: 1px solid {BORDER};
}}

QScrollBar:vertical {{
    background: {BG};
    width: 10px;
    margin: 0;
    border: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {BORDER_HI}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}

QScrollBar:horizontal {{
    background: {BG};
    height: 10px;
    margin: 0;
    border: 0;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: {BORDER_HI}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

#DetailsPanel {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}

#DetailsScroll, #DetailsContent {{
    background: transparent;
    border: 0;
}}

#DetailsName {{
    font-size: 17px;
    font-weight: 600;
    color: {TEXT};
}}

#DetailsCategory {{
    color: {TEXT_DIM};
    font-size: 12px;
}}

#DetailsDescription {{
    color: {TEXT};
    font-size: 13px;
    line-height: 1.4;
}}

#SectionLabel {{
    color: {TEXT_DIM};
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding-top: 4px;
}}

#MetaRow {{
    color: {TEXT};
    font-size: 12px;
}}

#MetaKey {{
    color: {TEXT_DIM};
    font-size: 12px;
}}

QTextEdit {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px;
    color: {TEXT};
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 11px;
}}

#EmptyHint {{
    color: {TEXT_DIM};
    font-size: 13px;
}}

QStatusBar {{
    background: {BG};
    border-top: 1px solid {BORDER};
    color: {TEXT_DIM};
    font-size: 11px;
}}

QStatusBar::item {{ border: 0; }}
"""


# ---------------------------------------------------------------- helpers
def make_avatar(letter: str, color: str, size: int = 36) -> QPixmap:
    """Return a circular colored avatar with a single letter. Used in the details panel."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.setPen(QColor("white"))
    f = QFont("Segoe UI", int(size * 0.42), QFont.Weight.Bold)
    p.setFont(f)
    p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, letter.upper())
    p.end()
    return pix


def make_logo(size: int = 28) -> QPixmap:
    """A small shield-shaped logo for the header. Drawn programmatically — no asset files needed."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    # Shield outline
    p.setBrush(QColor(ACCENT))
    p.setPen(Qt.PenStyle.NoPen)
    from PySide6.QtGui import QPainterPath
    path = QPainterPath()
    w, h = size, size
    path.moveTo(w * 0.5, h * 0.06)
    path.lineTo(w * 0.92, h * 0.22)
    path.lineTo(w * 0.92, h * 0.55)
    path.cubicTo(w * 0.92, h * 0.82, w * 0.72, h * 0.94, w * 0.5, h * 0.96)
    path.cubicTo(w * 0.28, h * 0.94, w * 0.08, h * 0.82, w * 0.08, h * 0.55)
    path.lineTo(w * 0.08, h * 0.22)
    path.closeSubpath()
    p.drawPath(path)
    # Checkmark
    pen = p.pen()
    pen.setColor(QColor("white"))
    pen.setWidthF(size * 0.10)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawLine(int(w * 0.30), int(h * 0.52), int(w * 0.45), int(h * 0.67))
    p.drawLine(int(w * 0.45), int(h * 0.67), int(w * 0.72), int(h * 0.38))
    p.end()
    return pix


def _path_context(exe: str) -> dict[str, str]:
    """Extract publisher/product hints from an executable's install path.

    The folder layout of a binary frequently gives away what it is, even when
    the binary's own version-info fields are empty. Examples we want to handle:

        C:\\Program Files\\GIGABYTE\\Control Center\\GCC.exe
          -> install_vendor='GIGABYTE', install_product='Control Center'

        C:\\Program Files\\TRCCCAP\\TRCC.exe
          -> install_vendor='TRCCCAP'

        C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.513.4821.0_x64__...\\app\\Codex.exe
          -> store_publisher='OpenAI', store_product='Codex'
    """
    if not exe:
        return {}
    parts = [x for x in exe.replace("/", "\\").split("\\") if x]
    out: dict[str, str] = {}

    # Microsoft Store: WindowsApps\Publisher.Product_version_arch_hash\...
    if "WindowsApps" in parts:
        idx = parts.index("WindowsApps")
        if idx + 1 < len(parts):
            pkg = parts[idx + 1].split("_")[0]
            if "." in pkg:
                pub, _, prod = pkg.partition(".")
                out["store_publisher"] = pub
                out["store_product"] = prod
            else:
                out["store_product"] = pkg

    # Program Files: usually <vendor>\<product>\<binary> or just <vendor>\<binary>
    for marker in ("Program Files (x86)", "Program Files"):
        if marker in parts:
            idx = parts.index(marker)
            if idx + 1 < len(parts):
                out["install_vendor"] = parts[idx + 1]
            if idx + 2 < len(parts) - 1:   # there's also a product folder
                out["install_product"] = parts[idx + 2]
            break

    return out


def _looks_like_code_name(file_desc: str, exe_name: str, product: str) -> bool:
    """Heuristic: does this FileDescription look like an internal code/abbreviation
    rather than a real product description? E.g. 'GCC', 'TRCC', 'CEF'."""
    if not file_desc:
        return False
    stem = os.path.splitext(exe_name)[0].lower() if exe_name else ""
    fd = file_desc.strip()
    if len(fd) <= 5 and fd == fd.upper():
        return True
    if stem and fd.lower() == stem:
        return True
    if product and fd.lower() == product.strip().lower() and len(fd) <= 6:
        return True
    return False


def _categorize_location(exe: str) -> str:
    """One-phrase summary of where on disk an executable lives."""
    if not exe:
        return ""
    p = exe.lower().replace("/", "\\")
    if "system32\\driverstore" in p:
        return "the Windows driver store"
    if "\\system32\\" in p or "\\syswow64\\" in p:
        return "a Windows system folder"
    if "\\systemapps\\" in p:
        return "the Windows shell system-apps folder"
    if "\\windowsapps\\" in p:
        return "a Microsoft Store install location"
    if "\\program files (x86)\\" in p:
        return "Program Files (x86)"
    if "\\program files\\" in p:
        return "Program Files"
    if "\\appdata\\local\\temp" in p or "\\windows\\temp" in p:
        return "a temporary folder (unusual for a real program)"
    if "\\$recycle.bin" in p:
        return "the Recycle Bin (very unusual)"
    if "\\downloads\\" in p:
        return "your Downloads folder (unusual for a real program)"
    if "\\appdata\\roaming" in p:
        return "your user profile (AppData\\Roaming — common for chat apps and Electron tools)"
    if "\\appdata\\local" in p:
        return "your user profile (AppData\\Local — common for browsers and IDEs)"
    if "\\users\\" in p:
        return "your user folder"
    return ""


def describe_process(record: dict[str, Any]) -> str:
    """Build a human-readable one-paragraph description for a process.

    Sources we pull from, in order of preference:
      1. Curated database entry — most reliable, written for humans.
      2. PE version-info FileDescription — what the binary claims to be,
         *if* it isn't just a short code-name like 'GCC' or 'TRCC'.
      3. Synthesised from signer cert + install path + parent + version info.
      4. A note about why we can't see anything (access denied).
    """
    a = record["assessment"]
    db = a.get("db_entry") or {}
    vi = a.get("version_info") or {}
    exe = record.get("exe") or ""
    name = record.get("name") or ""

    # 1. Curated DB description always wins.
    if db.get("description"):
        return db["description"]

    file_desc = (vi.get("FileDescription") or "").strip()
    product = (vi.get("ProductName") or "").strip()
    company = (vi.get("CompanyName") or "").strip()
    signer = (a.get("signer") or "").strip()
    publisher = db.get("publisher") or a.get("company") or company or signer or ""
    # Trim trailing punctuation so we don't get "Gen Digital Inc.." when the
    # company already includes a trailing period.
    publisher = publisher.strip().rstrip(".").strip()

    if record.get("access_limited"):
        return (
            "This process is protected — Windows didn't grant access to read "
            "its details. That's normal for core system processes like lsass.exe "
            "and Registry. There's nothing to investigate."
        )

    # Best guess at what category this publisher's stuff falls into.
    # E.g. "Gen Digital Inc." -> "Gen Digital publishes Norton, Avast, AVG…".
    purpose = purpose_for(publisher) or purpose_for(signer)

    # 2. Use the binary's own FileDescription unless it looks like an internal
    #    code-name ('GCC', 'TRCC', 'CEF') — in which case we'll synthesise
    #    something more informative from the path and certificate instead.
    is_code = _looks_like_code_name(file_desc, name, product)
    if file_desc and not is_code:
        out = file_desc.rstrip(".")
        if publisher:
            out += f" — by {publisher}."
        else:
            out += "."
        if product and product.lower() != file_desc.lower() and len(product) > 5:
            out += f" Part of {product}."
        if purpose:
            out += f" {purpose}"
        return out

    # 3. Synthesise. Pull every signal we have and turn it into a sentence.
    ctx = _path_context(exe)
    install_vendor = ctx.get("install_vendor", "")
    install_product = ctx.get("install_product", "")
    store_publisher = ctx.get("store_publisher", "")
    store_product = ctx.get("store_product", "")

    # Heuristic: build the most specific "product" phrase we can.
    product_phrase = ""
    if install_vendor and install_product:
        product_phrase = f"{install_vendor} {install_product}"
    elif store_publisher and store_product:
        product_phrase = f"{store_publisher} {store_product}"
    elif install_vendor:
        product_phrase = install_vendor
    elif store_product:
        product_phrase = store_product
    elif product and len(product) > 5:
        product_phrase = product

    chunks: list[str] = []

    # Lead sentence — "Appears to be part of X, published by Y."
    if product_phrase and publisher:
        # If publisher and product_phrase overlap, just say the product.
        if publisher.lower() in product_phrase.lower() or product_phrase.lower() in publisher.lower():
            chunks.append(f"Appears to be part of {product_phrase}.")
        else:
            chunks.append(f"Appears to be part of {product_phrase}, published by {publisher}.")
    elif product_phrase:
        chunks.append(f"Appears to be part of {product_phrase}.")
    elif publisher:
        chunks.append(f"Published by {publisher}.")
    else:
        chunks.append("Publisher information is missing from the executable.")

    # Install location category — only if it adds info beyond what we said above.
    location = _categorize_location(exe)
    if location and not product_phrase:
        chunks.append(f"It runs from {location}.")

    # Parent process — useful unless it's just the shell.
    parent = (record.get("parent_name") or "").strip()
    if parent and parent.lower() not in {"explorer.exe", "services.exe", "svchost.exe", ""}:
        chunks.append(f"Started by {parent}.")

    # Signature status.
    signed = a.get("signed")
    if signed is True:
        chunks.append("Windows verifies its digital signature.")
    elif signed is False:
        chunks.append("Its executable isn't digitally signed.")

    # Purpose hint from publisher → category mapping. Often the most useful
    # line for an unknown binary signed by a recognisable company.
    if purpose:
        chunks.append(purpose)

    # Mention the code-name so it's not lost — useful for searching online.
    if is_code and file_desc:
        chunks.append(f"(Internal code: {file_desc}.)")

    # Practical advice for the user instead of just "search online". The goal
    # is to let them decide whether to keep, close, or investigate the process.
    if signed is True:
        chunks.append(
            "If you don't recognise the product or publisher: you can try ending "
            "it via Task Manager. If a connected device, app, or Windows feature "
            "stops working, you'll know it was needed — a reboot will restore it. "
            "If it comes back on its own, it's set to auto-start."
        )
    elif signed is False:
        chunks.append(
            "It's unsigned, which is common for indie tools but worth a closer "
            "look — search the executable name and the install folder name "
            "together. Try ending it via Task Manager; if nothing obvious breaks, "
            "you probably don't need it."
        )
    else:
        chunks.append(
            "If you don't recognise it: search the executable name plus the "
            "install folder name. Try ending it via Task Manager — if "
            "something stops working, a reboot will restore it."
        )
    return " ".join(chunks)


class NumericItem(QTableWidgetItem):
    """A table item that sorts by an attached numeric value rather than its display string."""

    def __init__(self, display: str, sort_key: float):
        super().__init__(display)
        self._sort_key = sort_key

    def __lt__(self, other: "NumericItem") -> bool:  # type: ignore[override]
        if isinstance(other, NumericItem):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


# ---------------------------------------------------------------- stat card
class StatCard(QFrame):
    """Top-row summary card. Click-to-filter the table by the card's category."""
    clicked = Signal(str)   # emits the filter dropdown text to apply

    def __init__(
        self,
        label: str,
        filter_key: str = "All",
        value: str = "—",
        color: str | None = None,
    ) -> None:
        super().__init__()
        self.setObjectName("StatCard")
        self.setMinimumHeight(78)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._filter_key = filter_key

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)

        self.label = QLabel(label)
        self.label.setObjectName("StatLabel")
        self.value = QLabel(value)
        self.value.setObjectName("StatValue")
        if color:
            self.value.setStyleSheet(f"color: {color};")
        lay.addWidget(self.label)
        lay.addWidget(self.value)

    def set_value(self, v: int | str) -> None:
        self.value.setText(str(v))

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._filter_key)
        super().mousePressEvent(event)


class ClickableLabel(QLabel):
    """A QLabel that emits clicked() on left mouse press."""
    clicked = Signal()

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ---------------------------------------------------------------- worker
class ScanWorker(QObject):
    finished = Signal(list)
    failed = Signal(str)

    def run(self) -> None:
        try:
            results = scanner.collect()
            self.finished.emit(results)
        except Exception:
            self.failed.emit(traceback.format_exc())


class UpdateInstallWorker(QObject):
    """Downloads the new WhatsRunning.exe from GitHub Releases on a background
    thread, writes it to a temp location, then signals success with the temp
    path so MainWindow can spawn the swap-and-relaunch helper.

    Privacy note: a single HTTPS GET to GitHub Releases CDN, only when the
    user explicitly clicked the "Update now" button in the update dialog.
    The downloaded binary is written to %TEMP% — not yet applied to disk —
    until the user's process exits and the helper script runs.
    """
    progress = Signal(int)            # 0..100 percent
    finished = Signal(str)            # temp path of the downloaded .exe
    failed = Signal(str)

    def __init__(self, asset_url: str):
        super().__init__()
        self._url = asset_url

    def run(self) -> None:
        try:
            import tempfile
            import urllib.request

            req = urllib.request.Request(
                self._url,
                headers={"User-Agent": f"{APP_NAME}/{VERSION} self-update"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length") or 0)
                fd, temp_path = tempfile.mkstemp(suffix=".exe", prefix="WhatsRunning_new_")
                downloaded = 0
                with os.fdopen(fd, "wb") as out:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        out.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            self.progress.emit(int(downloaded * 100 / total))
            self.finished.emit(temp_path)
        except Exception as e:
            self.failed.emit(str(e))


def _write_swap_helper(new_exe_temp: str, target_exe: str) -> str:
    """Writes a small batch file that:
      1. Waits 3 seconds for the current WhatsRunning process to exit cleanly
      2. Copies the freshly-downloaded .exe over the existing one
      3. Launches the new .exe
      4. Deletes itself
    Returns the path of the helper. Caller is responsible for spawning it
    detached just before exit.

    The helper is a .bat file generated by our process (not downloaded),
    so it doesn't get Mark of the Web — Windows won't run a SmartScreen
    check on it.
    """
    import tempfile

    helper_fd, helper_path = tempfile.mkstemp(suffix=".bat", prefix="WhatsRunning_swap_")
    script = (
        "@echo off\r\n"
        "REM Auto-generated by WhatsRunning to swap the running .exe with\r\n"
        "REM a freshly-downloaded copy. Self-deletes when done.\r\n"
        "timeout /t 3 /nobreak >nul\r\n"
        f'move /y "{new_exe_temp}" "{target_exe}" >nul\r\n'
        f'start "" "{target_exe}"\r\n'
        f'del "%~f0"\r\n'
    )
    with os.fdopen(helper_fd, "w", newline="") as f:
        f.write(script)
    return helper_path


class UpdateWorker(QObject):
    """Checks GitHub for both newer app version AND newer process database,
    on a background thread, in a single user-triggered network call.

    Privacy note: makes up to two HTTPS GETs (to api.github.com and to
    raw.githubusercontent.com), only when the user explicitly clicks
    "Check for updates…". No personal data is sent — just the requests.
    If the database has a newer version, it's downloaded, validated, and
    saved to %APPDATA%\\WhatsRunning\\process_data.json automatically.
    """
    # result dict keys: 'app_update' (dict or None), 'db_updated' (dict or None)
    finished = Signal(dict)
    failed = Signal(str)

    @staticmethod
    def _version_tuple(v: str) -> tuple:
        """Parse '1.0.2' / 'v1.0.2' → (1, 0, 2) for numeric comparison.
        Returns (0,) if the string can't be parsed."""
        try:
            return tuple(int(p) for p in v.strip().lstrip("vV").split(".") if p)
        except (ValueError, AttributeError):
            return (0,)

    def run(self) -> None:
        try:
            import json
            import urllib.request
            import process_database

            result: dict = {"app_update": None, "db_updated": None}

            # ---- 1. Check for newer app release ----
            try:
                req = urllib.request.Request(
                    GITHUB_LATEST_RELEASE_API,
                    headers={
                        "User-Agent": f"{APP_NAME}/{VERSION} update-check",
                        "Accept": "application/vnd.github+json",
                    },
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    rel = json.loads(resp.read())
                latest = (rel.get("tag_name") or "").lstrip("vV").strip()
                # Only flag an update if the published version is STRICTLY
                # greater than ours. If they're equal, we're current. If
                # we're greater (running a pre-release / local build), we
                # also treat that as "up to date" — never tell users to
                # downgrade.
                if latest and self._version_tuple(latest) > self._version_tuple(VERSION):
                    # Find the WhatsRunning.exe asset's direct download URL,
                    # so the in-app updater can fetch it without going via
                    # the browser (which would add Mark of the Web).
                    asset_url = ""
                    asset_size = 0
                    for asset in rel.get("assets", []) or []:
                        if (asset.get("name") or "").lower() == "whatsrunning.exe":
                            asset_url = asset.get("browser_download_url") or ""
                            asset_size = asset.get("size") or 0
                            break
                    result["app_update"] = {
                        "version": latest,
                        "url": rel.get("html_url") or GITHUB_RELEASES_PAGE,
                        "asset_url": asset_url,
                        "asset_size": asset_size,
                        "notes": rel.get("body") or "",
                    }
            except Exception:
                # If we can't reach the release API at all, treat the whole
                # check as failed so the user gets a clear message rather
                # than silent "up to date" when we don't actually know.
                raise

            # ---- 2. Check for newer process database, apply if newer ----
            try:
                req = urllib.request.Request(
                    DATABASE_URL,
                    headers={
                        "User-Agent": f"{APP_NAME}/{VERSION} db-update",
                        "Accept": "application/json",
                    },
                )
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw = resp.read()
                data = json.loads(raw)
                if not isinstance(data, dict) or "processes" not in data:
                    # Database fetch returned something invalid — skip but
                    # don't fail the whole check (app-update result still useful)
                    pass
                else:
                    new_ver = data.get("version", "")
                    cur_ver = process_database.DATA_VERSION
                    if new_ver and new_ver != cur_ver:
                        # Apply the update silently: user explicitly clicked
                        # Check for updates, that's authorisation enough.
                        dest = process_database.appdata_path()
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "wb") as f:
                            f.write(raw)
                        process_database.reload()
                        result["db_updated"] = {
                            "version": new_ver,
                            "count": len(data.get("processes", {})),
                        }
            except Exception:
                # DB-side errors are non-fatal — app-update part may still
                # have succeeded. Just skip the DB update silently.
                pass

            self.finished.emit(result)
        except Exception as e:
            self.failed.emit(str(e))


# ---------------------------------------------------------------- details panel
class DetailsPanel(QWidget):
    # Action signals — the panel itself doesn't run any subprocesses or kill
    # anything; MainWindow connects to these and does the work.
    end_requested = Signal(dict)
    open_location_requested = Signal(dict)
    virustotal_requested = Signal(dict)
    search_requested = Signal(dict)
    copy_path_requested = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("DetailsPanel")
        self.setMinimumWidth(380)
        self.setMaximumWidth(520)
        self._current_record: dict[str, Any] | None = None

        # The panel itself is just a styled border with no padding — the
        # content sits in a scroll area so long descriptions / many indicators
        # don't push other fields off-screen on narrow windows.
        wrapper = QVBoxLayout(self)
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(0)

        scroll = QScrollArea()
        scroll.setObjectName("DetailsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        wrapper.addWidget(scroll)

        content = QWidget()
        content.setObjectName("DetailsContent")
        scroll.setWidget(content)

        outer = QVBoxLayout(content)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(12)

        # Title row: avatar + name + category
        title_row = QHBoxLayout()
        title_row.setSpacing(12)
        self.avatar = QLabel()
        self.avatar.setFixedSize(44, 44)
        title_row.addWidget(self.avatar)

        name_box = QVBoxLayout()
        name_box.setSpacing(2)
        self.name_lbl = QLabel("No process selected")
        self.name_lbl.setObjectName("DetailsName")
        self.cat_lbl = QLabel("Pick a row to see details")
        self.cat_lbl.setObjectName("DetailsCategory")
        name_box.addWidget(self.name_lbl)
        name_box.addWidget(self.cat_lbl)
        title_row.addLayout(name_box, 1)
        outer.addLayout(title_row)

        # Risk badge (a styled label, set in update())
        self.risk_lbl = QLabel("")
        self.risk_lbl.setMinimumHeight(26)
        self.risk_lbl.setVisible(False)
        outer.addWidget(self.risk_lbl)

        # Description
        self.desc_lbl = QLabel("Run a scan, then click any process in the list to learn what it is and whether it should be there.")
        self.desc_lbl.setObjectName("DetailsDescription")
        self.desc_lbl.setWordWrap(True)
        outer.addWidget(self.desc_lbl)

        # Why this risk (indicators + positives)
        self.why_label = QLabel("WHY THIS RISK")
        self.why_label.setObjectName("SectionLabel")
        self.why_label.setVisible(False)
        outer.addWidget(self.why_label)

        self.why_box = QLabel("")
        self.why_box.setWordWrap(True)
        self.why_box.setTextFormat(Qt.TextFormat.RichText)
        self.why_box.setVisible(False)
        outer.addWidget(self.why_box)

        # Metadata
        self.meta_label = QLabel("DETAILS")
        self.meta_label.setObjectName("SectionLabel")
        self.meta_label.setVisible(False)
        outer.addWidget(self.meta_label)

        self.meta_grid = QVBoxLayout()
        self.meta_grid.setSpacing(4)
        outer.addLayout(self.meta_grid)
        self._meta_widgets: list[QWidget] = []

        # Command line
        self.cmd_label = QLabel("COMMAND LINE")
        self.cmd_label.setObjectName("SectionLabel")
        self.cmd_label.setVisible(False)
        outer.addWidget(self.cmd_label)

        self.cmd_edit = QTextEdit()
        self.cmd_edit.setReadOnly(True)
        self.cmd_edit.setMaximumHeight(110)
        self.cmd_edit.setVisible(False)
        outer.addWidget(self.cmd_edit)

        # Action buttons — what the user can DO with this process. Hidden
        # until a process is selected, then shown.
        self.actions_label = QLabel("ACTIONS")
        self.actions_label.setObjectName("SectionLabel")
        self.actions_label.setVisible(False)
        outer.addWidget(self.actions_label)

        self.actions_grid = QGridLayout()
        self.actions_grid.setSpacing(6)
        outer.addLayout(self.actions_grid)

        self.btn_locate = QPushButton("📂  Open file location")
        self.btn_copy = QPushButton("📋  Copy path")
        self.btn_search = QPushButton("🔍  Search online")
        self.btn_virustotal = QPushButton("🛡  Check on VirusTotal")
        self.btn_end = QPushButton("⨯  End process")
        for b in (self.btn_locate, self.btn_copy, self.btn_search, self.btn_virustotal):
            b.setObjectName("ActionButton")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_end.setObjectName("DangerButton")
        self.btn_end.setCursor(Qt.CursorShape.PointingHandCursor)

        # 2x3 grid: [Locate] [Copy] / [Search] [VirusTotal] / [End] spans 2 cols
        self.actions_grid.addWidget(self.btn_locate, 0, 0)
        self.actions_grid.addWidget(self.btn_copy, 0, 1)
        self.actions_grid.addWidget(self.btn_search, 1, 0)
        self.actions_grid.addWidget(self.btn_virustotal, 1, 1)
        self.actions_grid.addWidget(self.btn_end, 2, 0, 1, 2)
        for b in (self.btn_locate, self.btn_copy, self.btn_search,
                  self.btn_virustotal, self.btn_end):
            b.setVisible(False)

        self.btn_locate.clicked.connect(self._on_locate)
        self.btn_copy.clicked.connect(self._on_copy)
        self.btn_search.clicked.connect(self._on_search)
        self.btn_virustotal.clicked.connect(self._on_virustotal)
        self.btn_end.clicked.connect(self._on_end)

        outer.addStretch(1)

    # ---- action button click handlers ----
    # Each one just re-emits as a signal so MainWindow does the real work.
    def _emit_for_current(self, sig: Signal) -> None:
        if self._current_record:
            sig.emit(self._current_record)

    def _on_locate(self) -> None: self._emit_for_current(self.open_location_requested)
    def _on_copy(self) -> None: self._emit_for_current(self.copy_path_requested)
    def _on_search(self) -> None: self._emit_for_current(self.search_requested)
    def _on_virustotal(self) -> None: self._emit_for_current(self.virustotal_requested)
    def _on_end(self) -> None: self._emit_for_current(self.end_requested)

    def _add_meta(self, key: str, value: str) -> None:
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        k = QLabel(key)
        k.setObjectName("MetaKey")
        k.setMinimumWidth(96)
        v = QLabel(value)
        v.setObjectName("MetaRow")
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        h.addWidget(k)
        h.addWidget(v, 1)
        self.meta_grid.addWidget(row)
        self._meta_widgets.append(row)

    def _clear_meta(self) -> None:
        for w in self._meta_widgets:
            w.setParent(None)
            w.deleteLater()
        self._meta_widgets.clear()

    def show_process(self, record: dict[str, Any]) -> None:
        self._current_record = record
        name = record["name"]
        a = record["assessment"]
        db = a.get("db_entry") or {}
        category = db.get("category", "Unknown")

        # Avatar
        color = CATEGORY_COLORS.get(category, CATEGORY_COLORS["Unknown"])
        letter = name[0] if name else "?"
        self.avatar.setPixmap(make_avatar(letter, color, 44))

        self.name_lbl.setText(name)
        self.cat_lbl.setText(f"{category} • PID {record['pid']}")

        # Risk badge
        risk_label = a["risk_label"]
        risk_color = RISK_COLORS[risk_label]
        self.risk_lbl.setText(f"  ●  {risk_label}")
        self.risk_lbl.setStyleSheet(
            f"background: {risk_color}22; "
            f"color: {risk_color}; "
            f"border: 1px solid {risk_color}55; "
            f"border-radius: 12px; "
            f"padding: 4px 12px; "
            f"font-weight: 600; "
            f"font-size: 12px;"
        )
        self.risk_lbl.setVisible(True)
        self.risk_lbl.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        self.desc_lbl.setText(describe_process(record))

        # Why this risk
        indicators = a["indicators"]
        positives = a["positives"]
        if indicators or positives:
            parts = []
            for item in indicators:
                parts.append(f"<span style='color:{RISK_COLORS['Suspicious']};'>•</span>&nbsp; {item}")
            for item in positives:
                parts.append(f"<span style='color:{RISK_COLORS['Trusted']};'>✓</span>&nbsp; {item}")
            self.why_box.setText("<br><br>".join(parts))
            self.why_label.setVisible(True)
            self.why_box.setVisible(True)
        else:
            self.why_label.setVisible(False)
            self.why_box.setVisible(False)

        # Metadata
        self._clear_meta()
        publisher = db.get("publisher") or a["version_info"].get("CompanyName") or "—"
        path = record.get("exe") or ("(access denied)" if record.get("access_limited") else "—")
        signed = a["signed"]
        signed_str = "Yes" if signed else ("No" if signed is False else "Not checked")
        self._add_meta("Publisher", publisher)
        self._add_meta("Path", path)
        self._add_meta("Signed", signed_str)
        self._add_meta("Parent", f"{record.get('parent_name') or '—'} (PID {record.get('ppid') or '—'})")
        self._add_meta("Memory", record["memory_str"])
        self._add_meta("CPU", f"{record['cpu']:.1f}%")
        self._add_meta("Threads", str(record["num_threads"]))
        self._add_meta("Connections", str(record["connections"]))
        self._add_meta("User", record.get("username") or "—")
        self._add_meta("Running for", record["age_str"])
        self.meta_label.setVisible(True)

        # Command line
        cl = record.get("cmdline") or ""
        if cl and cl.strip().lower() != record.get("exe", "").lower().strip():
            self.cmd_edit.setPlainText(cl)
            self.cmd_label.setVisible(True)
            self.cmd_edit.setVisible(True)
        else:
            self.cmd_label.setVisible(False)
            self.cmd_edit.setVisible(False)

        # Actions row — visible whenever a process is selected. Some are
        # disabled if we lack the data they need.
        self.actions_label.setVisible(True)
        has_path = bool(record.get("exe"))
        self.btn_locate.setVisible(True);     self.btn_locate.setEnabled(has_path)
        self.btn_copy.setVisible(True);       self.btn_copy.setEnabled(has_path)
        self.btn_search.setVisible(True);     self.btn_search.setEnabled(True)
        self.btn_virustotal.setVisible(True); self.btn_virustotal.setEnabled(has_path)
        self.btn_end.setVisible(True);        self.btn_end.setEnabled(True)

    def clear(self) -> None:
        self._current_record = None
        self.avatar.clear()
        self.name_lbl.setText("No process selected")
        self.cat_lbl.setText("Pick a row to see details")
        self.desc_lbl.setText("Run a scan, then click any process in the list to learn what it is and whether it should be there.")
        self.risk_lbl.setVisible(False)
        self.why_label.setVisible(False)
        self.why_box.setVisible(False)
        self.meta_label.setVisible(False)
        self.cmd_label.setVisible(False)
        self.cmd_edit.setVisible(False)
        self._clear_meta()
        # Hide all action buttons until the next selection.
        for b in (self.btn_locate, self.btn_copy, self.btn_search,
                  self.btn_virustotal, self.btn_end):
            b.setVisible(False)
        self.actions_label.setVisible(False)


# ---------------------------------------------------------------- about dialog
class AboutDialog(QDialog):
    """Modal 'About' window — branding, version, links."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("AboutDialog")
        self.setWindowTitle(f"About {APP_NAME}")
        self.setFixedSize(460, 420)
        self.setModal(True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 20)
        outer.setSpacing(14)

        # Logo, centred
        logo = QLabel()
        logo.setPixmap(make_logo(72))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(logo)

        # Title
        title = QLabel(APP_NAME)
        title.setObjectName("AboutTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(title)

        # Tagline
        tag = QLabel(TAGLINE)
        tag.setObjectName("AboutTagline")
        tag.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tag.setWordWrap(True)
        outer.addWidget(tag)

        outer.addSpacing(6)

        # Body — short paragraph explaining what the app is
        body = QLabel(
            f"{APP_NAME} inspects every process running on your PC and tells you, "
            f"in plain English, what each one is and whether it should be there. "
            f"Scans only run when you click the button — nothing happens in the background."
        )
        body.setObjectName("AboutBody")
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(body)

        outer.addSpacing(6)

        # Version + author row
        meta = QLabel(f"Version {VERSION}   •   by {AUTHOR}   •   © {COPYRIGHT_YEAR}")
        meta.setObjectName("AboutVersion")
        meta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(meta)

        outer.addStretch(1)

        # Action row
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addStretch(1)

        site_btn = QPushButton("Visit website")
        site_btn.setObjectName("LinkButton")
        site_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        site_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(WEBSITE_URL)))
        row.addWidget(site_btn)

        donate_btn = QPushButton("♥  Support development")
        donate_btn.setObjectName("PrimaryLinkButton")
        donate_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        donate_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(DONATION_URL)))
        row.addWidget(donate_btn)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("LinkButton")
        close_btn.clicked.connect(self.accept)
        row.addWidget(close_btn)
        outer.addLayout(row)


# ---------------------------------------------------------------- main window
class MainWindow(QMainWindow):
    COLS = ["Process", "PID", "CPU", "Memory", "Category", "Risk"]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Windows Process Inspector")
        self.setWindowIcon(QIcon(make_logo(64)))
        self.resize(1240, 780)
        self.setMinimumSize(QSize(1000, 640))

        self._records: list[dict[str, Any]] = []
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        self._update_thread: QThread | None = None
        self._update_worker: UpdateWorker | None = None
        self._install_thread: QThread | None = None
        self._install_worker: UpdateInstallWorker | None = None
        self._progress_box: QMessageBox | None = None

        self._build_menubar()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(20, 16, 20, 16)
        body_lay.setSpacing(14)
        body_lay.addLayout(self._build_stats())
        body_lay.addLayout(self._build_toolbar())
        body_lay.addWidget(self._build_splitter(), 1)
        root.addWidget(body, 1)

        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        self.status_label = QLabel("Ready. Click Scan Now to inspect every running process.")
        sb.addWidget(self.status_label, 1)
        sb.addPermanentWidget(QLabel(f"{APP_NAME} {VERSION}"))
        self.setStatusBar(sb)

    def _build_menubar(self) -> None:
        bar = self.menuBar()

        file_menu = bar.addMenu("&File")
        refresh = QAction("&Rescan", self)
        refresh.setShortcut("F5")
        refresh.triggered.connect(self.start_scan)
        file_menu.addAction(refresh)
        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        help_menu = bar.addMenu("&Help")
        check_updates = QAction("Check for &updates…", self)
        check_updates.triggered.connect(self.check_for_updates)
        help_menu.addAction(check_updates)
        help_menu.addSeparator()
        support = QAction("&Support development…", self)
        support.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(DONATION_URL)))
        help_menu.addAction(support)
        website = QAction("&Visit website…", self)
        website.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(WEBSITE_URL)))
        help_menu.addAction(website)
        help_menu.addSeparator()
        about = QAction(f"&About {APP_NAME}", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)

    def show_about(self) -> None:
        dlg = AboutDialog(self)
        dlg.exec()

    # -- update check (single button, plain English) ------------------------------
    def check_for_updates(self) -> None:
        """User clicked Help → Check for updates. Single unified flow that
        checks for both a newer app version and a newer process database,
        on a background thread."""
        if getattr(self, "_update_thread", None) is not None:
            return  # already running
        self.status_label.setText("Checking for updates…")
        thread = QThread(self)
        worker = UpdateWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_updates_done)
        worker.failed.connect(self._on_updates_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(worker.deleteLater)
        self._update_thread = thread
        self._update_worker = worker
        thread.start()

    def _on_updates_done(self, result: dict) -> None:
        self._update_thread = None
        self._update_worker = None
        import process_database

        app_update = result.get("app_update")
        db_updated = result.get("db_updated")

        # Case 1: a new app version is available.
        if app_update:
            self.status_label.setText(f"Update available: v{app_update['version']}.")
            # Is this running as a packaged .exe (where we can self-update)
            # or from source (where we can only point at the download page)?
            is_packaged = getattr(sys, "frozen", False)
            can_self_update = is_packaged and bool(app_update.get("asset_url"))

            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Information)
            box.setWindowTitle("Update available")
            box.setTextFormat(Qt.TextFormat.RichText)
            body = (
                f"<b>A new version of {APP_NAME} is available.</b><br><br>"
                f"You have: <code>v{VERSION}</code><br>"
                f"Latest:&nbsp;&nbsp;<code>v{app_update['version']}</code>"
            )
            if db_updated:
                body += (
                    "<br><br>The process database was also refreshed in the "
                    "background — you now have the latest descriptions."
                )
            if can_self_update:
                body += (
                    "<br><br>Click <b>Update now</b> to download and apply "
                    "the update — the app will briefly close and reopen."
                )
            box.setText(body)
            notes = app_update.get("notes") or ""
            if notes:
                box.setDetailedText(notes[:2000])

            if can_self_update:
                box.setStandardButtons(
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                yes_btn = box.button(QMessageBox.StandardButton.Yes)
                yes_btn.setText("Update now")
                no_btn = box.button(QMessageBox.StandardButton.No)
                no_btn.setText("Later")
                box.setDefaultButton(yes_btn)
                if box.exec() == QMessageBox.StandardButton.Yes:
                    self._begin_self_update(app_update["asset_url"])
            else:
                # Source build — can only point at the GitHub page.
                box.setStandardButtons(
                    QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Cancel
                )
                open_btn = box.button(QMessageBox.StandardButton.Open)
                open_btn.setText("Open download page")
                box.setDefaultButton(open_btn)
                if box.exec() == QMessageBox.StandardButton.Open:
                    QDesktopServices.openUrl(QUrl(app_update["url"]))
            return

        # Case 2: app is current, but the database was refreshed.
        if db_updated:
            self.status_label.setText(
                f"Process database refreshed ({db_updated['count']} entries)."
            )
            QMessageBox.information(
                self,
                "Up to date",
                f"You're running the latest version of {APP_NAME}.<br><br>"
                f"The process database was also refreshed — your next scan "
                f"will use the new descriptions.",
            )
            return

        # Case 3: everything's current.
        self.status_label.setText(f"You're up to date (v{VERSION}).")
        QMessageBox.information(
            self,
            "Up to date",
            f"You're on the latest version of {APP_NAME} (<b>v{VERSION}</b>) "
            f"with the latest process database.<br><br>"
            f"{APP_NAME} only checks for updates when you click this — "
            f"never in the background.",
        )

    def _on_updates_failed(self, error: str) -> None:
        self._update_thread = None
        self._update_worker = None
        self.status_label.setText("Couldn't check for updates.")
        # Plain-English error — never show users a stacktrace, URL, or HTTP
        # status code unless they explicitly ask for "details".
        QMessageBox.warning(
            self,
            "Couldn't check for updates",
            "Couldn't reach the update server.<br><br>"
            "This usually means your internet connection isn't working, "
            "or GitHub is temporarily down. Try again in a few minutes.",
        )

    # -- in-app self-update (download + swap + relaunch) -------------------------
    def _begin_self_update(self, asset_url: str) -> None:
        """User clicked 'Update now'. Spawn a worker that downloads the new
        .exe to a temp path, show a progress dialog, then on completion
        spawn the swap-and-relaunch helper and exit."""
        # Progress dialog (modal so the user knows the app is busy).
        self._progress_box = QMessageBox(self)
        self._progress_box.setIcon(QMessageBox.Icon.Information)
        self._progress_box.setWindowTitle("Updating WhatsRunning")
        self._progress_box.setText(
            "Downloading the latest version…<br><br>"
            "<b>0%</b>"
        )
        self._progress_box.setStandardButtons(QMessageBox.StandardButton.NoButton)
        self._progress_box.setModal(True)
        self._progress_box.show()

        thread = QThread(self)
        worker = UpdateInstallWorker(asset_url)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_install_progress)
        worker.finished.connect(self._on_install_done)
        worker.failed.connect(self._on_install_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(worker.deleteLater)
        self._install_thread = thread
        self._install_worker = worker
        thread.start()

    def _on_install_progress(self, percent: int) -> None:
        if getattr(self, "_progress_box", None):
            self._progress_box.setText(
                f"Downloading the latest version…<br><br><b>{percent}%</b>"
            )

    def _on_install_done(self, temp_exe_path: str) -> None:
        self._install_thread = None
        self._install_worker = None
        if getattr(self, "_progress_box", None):
            self._progress_box.close()
            self._progress_box = None

        # Spawn the swap-and-relaunch helper as a detached process so it
        # survives our exit, then quit. The helper does the actual file
        # replacement after we're gone (Windows won't let us overwrite a
        # running .exe).
        try:
            target_exe = sys.executable
            helper = _write_swap_helper(temp_exe_path, target_exe)
            # CREATE_NO_WINDOW + DETACHED_PROCESS so no console flashes.
            creationflags = 0x00000008 | 0x08000000  # DETACHED | NO_WINDOW
            subprocess.Popen(
                ["cmd.exe", "/c", helper],
                creationflags=creationflags,
                close_fds=True,
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Update problem",
                "Downloaded the update but couldn't start the install helper.<br><br>"
                "You can manually replace your existing WhatsRunning.exe "
                "with the file at:<br><code>" + temp_exe_path + "</code>",
            )
            return

        # Goodbye — the helper will relaunch us once the swap is done.
        QApplication.quit()

    def _on_install_failed(self, error: str) -> None:
        self._install_thread = None
        self._install_worker = None
        if getattr(self, "_progress_box", None):
            self._progress_box.close()
            self._progress_box = None
        QMessageBox.warning(
            self,
            "Update failed",
            "Couldn't download the update.<br><br>"
            "This usually means your internet connection dropped or "
            "GitHub is temporarily down. Try again in a few minutes — "
            "your current copy of WhatsRunning is untouched.",
        )

    # -- builders -----------------------------------------------------------------
    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("Header")
        header.setFixedHeight(64)
        h = QHBoxLayout(header)
        h.setContentsMargins(20, 0, 20, 0)
        h.setSpacing(12)

        logo = QLabel()
        logo.setPixmap(make_logo(28))
        h.addWidget(logo)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        t1 = QLabel(APP_NAME)
        t1.setObjectName("AppName")
        t2 = QLabel("Windows Process Inspector")
        t2.setObjectName("AppSub")
        title_box.addWidget(t1)
        title_box.addWidget(t2)
        h.addLayout(title_box)
        h.addStretch(1)

        self.header_status = ClickableLabel("idle")
        self.header_status.setObjectName("StatusText")
        self.header_status.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header_status.clicked.connect(self._on_header_status_clicked)
        h.addWidget(self.header_status)
        return header

    def _on_header_status_clicked(self) -> None:
        """If the header is showing a 'worth a look' message, jump to that filter."""
        if not self._records:
            return
        text = self.header_status.text().lower()
        if "worth a look" in text:
            self._apply_filter("Anything suspicious+")
        elif "nothing suspicious" in text:
            self._apply_filter("All")

    def _build_stats(self) -> QHBoxLayout:
        lay = QHBoxLayout()
        lay.setSpacing(12)
        self.card_total = StatCard("Total Processes", filter_key="All")
        self.card_trusted = StatCard("Trusted", filter_key="Trusted only",
                                     color=RISK_COLORS["Trusted"])
        self.card_known = StatCard("Known", filter_key="Known only",
                                   color=RISK_COLORS["Known"])
        self.card_unknown = StatCard("Unknown", filter_key="Unknown only",
                                     color=RISK_COLORS["Unknown"])
        # The "Suspicious" card sums Low Risk + Suspicious, so filter to
        # "Anything suspicious+" (which includes both) when clicked.
        self.card_sus = StatCard("Suspicious", filter_key="Anything suspicious+",
                                 color=RISK_COLORS["Suspicious"])
        self.card_high = StatCard("High Risk", filter_key="High risk only",
                                  color=RISK_COLORS["High Risk"])
        for c in (self.card_total, self.card_trusted, self.card_known,
                  self.card_unknown, self.card_sus, self.card_high):
            c.clicked.connect(self._apply_filter)
            lay.addWidget(c)
        return lay

    def _apply_filter(self, filter_text: str) -> None:
        """Switch the filter dropdown to the given option, if it exists."""
        idx = self.filter_box.findText(filter_text)
        if idx >= 0:
            self.filter_box.setCurrentIndex(idx)

    def _build_toolbar(self) -> QHBoxLayout:
        lay = QHBoxLayout()
        lay.setSpacing(10)
        self.scan_btn = QPushButton("⟳  Scan Now")
        self.scan_btn.setObjectName("ScanButton")
        self.scan_btn.setMinimumHeight(38)
        self.scan_btn.clicked.connect(self.start_scan)
        lay.addWidget(self.scan_btn)

        self.filter_box = QComboBox()
        self.filter_box.addItems([
            "All", "Trusted only", "Known only", "Unknown only",
            "Suspicious only", "High risk only", "Anything suspicious+",
        ])
        self.filter_box.setMinimumHeight(38)
        self.filter_box.setMinimumWidth(180)
        self.filter_box.currentIndexChanged.connect(self._refresh_table)
        lay.addWidget(self.filter_box)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name, publisher, or path…")
        self.search.setMinimumHeight(38)
        self.search.textChanged.connect(self._refresh_table)
        lay.addWidget(self.search, 1)
        return lay

    def _build_splitter(self) -> QSplitter:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(10)

        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.itemSelectionChanged.connect(self._on_select)
        # Belt-and-braces: cellClicked fires on EVERY click, even when the user
        # clicks the row that's already selected (which itemSelectionChanged
        # silently ignores). Without this, clicking the auto-selected first
        # row after a filter change wouldn't refresh the details panel.
        self.table.cellClicked.connect(self._on_cell_clicked)

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in (1, 2, 3, 4, 5):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setMinimumSectionSize(72)

        # Empty-state placeholder lives inside the table viewport so it floats
        # in the empty space. Install an event filter on the viewport so we
        # catch its own resize events, not just the main window's.
        self._empty_hint = QLabel("Click Scan Now to inspect every running process on this PC.")
        self._empty_hint.setObjectName("EmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setWordWrap(True)
        self._empty_hint.setParent(self.table.viewport())
        self.table.viewport().installEventFilter(self)
        self._reposition_hint()

        self.details = DetailsPanel()
        # Wire the panel's action buttons to the MainWindow handlers below.
        self.details.end_requested.connect(self._action_end)
        self.details.open_location_requested.connect(self._action_open_location)
        self.details.virustotal_requested.connect(self._action_virustotal)
        self.details.search_requested.connect(self._action_search_online)
        self.details.copy_path_requested.connect(self._action_copy_path)

        # Right-click context menu on the table — same set of actions as the
        # buttons, accessible without first selecting the row.
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)

        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([820, 400])
        return splitter

    def _reposition_hint(self) -> None:
        if self._empty_hint:
            vp = self.table.viewport()
            # Leave a 16px horizontal margin so the hint never butts against
            # the viewport edge, and clamp y to >= 0 so it stays visible even
            # in very short viewports.
            margin = 16
            width = max(120, vp.width() - margin * 2)
            height = 100
            x = margin
            y = max(0, (vp.height() - height) // 2)
            self._empty_hint.setGeometry(x, y, width, height)

    def resizeEvent(self, event):  # type: ignore[override]
        super().resizeEvent(event)
        self._reposition_hint()

    def eventFilter(self, obj, event):  # type: ignore[override]
        # The viewport can resize independently of the main window — e.g. when
        # the splitter handle moves. Catch that here.
        if obj is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self._reposition_hint()
        return super().eventFilter(obj, event)

    # -- scan ---------------------------------------------------------------------
    def start_scan(self) -> None:
        if self._scan_thread is not None:
            return
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.header_status.setText("scanning")
        self.status_label.setText("Enumerating processes and running heuristics…")
        self._empty_hint.setText("Scanning… this usually takes a second or two.")
        self._empty_hint.show()

        thread = QThread(self)
        worker = ScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_scan_done)
        worker.failed.connect(self._on_scan_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(worker.deleteLater)
        self._scan_thread = thread
        self._scan_worker = worker
        thread.start()

    def _on_scan_done(self, results: list[dict[str, Any]]) -> None:
        self._records = results
        s = scanner.summary(results)
        self.card_total.set_value(s["Total"])
        self.card_trusted.set_value(s["Trusted"])
        self.card_known.set_value(s["Known"])
        self.card_unknown.set_value(s["Unknown"])
        self.card_sus.set_value(s["Suspicious"] + s["Low Risk"])
        self.card_high.set_value(s["High Risk"])
        self._refresh_table()
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("⟳  Re-scan")
        self._scan_thread = None
        self._scan_worker = None
        when = datetime.now().strftime("%H:%M:%S")
        sus_count = s["High Risk"] + s["Suspicious"] + s["Low Risk"]
        if sus_count:
            self.header_status.setText(f"{sus_count} item(s) worth a look")
            self.header_status.setStyleSheet(f"color: {RISK_COLORS['Suspicious']};")
        else:
            self.header_status.setText("nothing suspicious found")
            self.header_status.setStyleSheet(f"color: {RISK_COLORS['Trusted']};")
        self.status_label.setText(f"Scanned {s['Total']} processes at {when}.")

    def _on_scan_failed(self, tb: str) -> None:
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("⟳  Scan Now")
        self.header_status.setText("scan failed")
        self.header_status.setStyleSheet(f"color: {RISK_COLORS['High Risk']};")
        self.status_label.setText("Scan failed — see console for details.")
        print(tb, file=sys.stderr)
        self._scan_thread = None
        self._scan_worker = None

    # -- table --------------------------------------------------------------------
    def _filtered(self) -> list[dict[str, Any]]:
        mode = self.filter_box.currentText()
        q = self.search.text().strip().lower()

        def keep(r: dict[str, Any]) -> bool:
            label = r["assessment"]["risk_label"]
            if mode == "Trusted only" and label != "Trusted": return False
            if mode == "Known only" and label != "Known": return False
            if mode == "Unknown only" and label != "Unknown": return False
            if mode == "Suspicious only" and label != "Suspicious": return False
            if mode == "High risk only" and label != "High Risk": return False
            if mode == "Anything suspicious+" and r["assessment"]["risk"] < scanner.RISK_LOW: return False
            if q:
                hay = " ".join((
                    r["name"], r.get("exe", ""), r["assessment"].get("company", ""),
                    (r["assessment"].get("db_entry") or {}).get("publisher", ""),
                )).lower()
                if q not in hay: return False
            return True

        return [r for r in self._records if keep(r)]

    def _refresh_table(self) -> None:
        rows = self._filtered()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            a = r["assessment"]
            db = a.get("db_entry") or {}
            category = db.get("category", "Unknown")

            # Process column: name; tooltip shows the description + path so the
            # user can preview without selecting.
            name_item = QTableWidgetItem(r["name"])
            name_item.setData(Qt.ItemDataRole.UserRole, r)
            desc_preview = describe_process(r)
            path_line = r.get("exe") or "(path not available)"
            tip = f"<b>{r['name']}</b><br>{desc_preview}<br><br><i>{path_line}</i>"
            name_item.setToolTip(tip)
            cat_color = CATEGORY_COLORS.get(category, CATEGORY_COLORS["Unknown"])
            name_item.setForeground(QColor(TEXT))
            # Leading colored dot to hint at the category visually
            name_item.setText(f"  {r['name']}")
            self.table.setItem(i, 0, name_item)

            self.table.setItem(i, 1, NumericItem(str(r["pid"]), r["pid"]))
            self.table.setItem(i, 2, NumericItem(f"{r['cpu']:.1f}%", r["cpu"]))
            self.table.setItem(i, 3, NumericItem(r["memory_str"], r["memory"]))

            cat_item = QTableWidgetItem(category)
            cat_item.setForeground(QColor(cat_color))
            self.table.setItem(i, 4, cat_item)

            risk_label = a["risk_label"]
            risk_item = QTableWidgetItem(f"●  {risk_label}")
            risk_item.setForeground(QColor(RISK_COLORS[risk_label]))
            font = risk_item.font()
            font.setWeight(QFont.Weight.DemiBold)
            risk_item.setFont(font)
            # Numeric sort key so "High Risk" sorts above "Trusted".
            risk_sort = NumericItem(f"●  {risk_label}", a["risk"])
            risk_sort.setForeground(QColor(RISK_COLORS[risk_label]))
            risk_sort.setFont(font)
            self.table.setItem(i, 5, risk_sort)

        self.table.setSortingEnabled(True)
        self._empty_hint.setVisible(len(rows) == 0)
        if len(rows) == 0 and self._records:
            self._empty_hint.setText("Nothing matches that filter.")
        elif len(rows) == 0:
            self._empty_hint.setText("Click Scan Now to inspect every running process on this PC.")
        if rows:
            # Be explicit: setCurrentCell + selectRow + manual show. Each one
            # individually has edge cases where it fails to refresh the details
            # panel (e.g., when the new row 0 happens to be at the same model
            # index as the previously-selected row, no signal fires). Doing
            # all three guarantees the side panel matches what's visible.
            self.table.setCurrentCell(0, 0)
            self.table.selectRow(0)
            self._show_record_at(0)

    def _on_cell_clicked(self, row: int, column: int) -> None:
        """Fires on every cell click, even when the row was already selected."""
        self._show_record_at(row)

    def _show_record_at(self, row: int) -> None:
        """Look up the record attached to row `row` and push it to the details panel."""
        if row < 0:
            return
        item = self.table.item(row, 0)
        if not item:
            return
        record = item.data(Qt.ItemDataRole.UserRole)
        if record:
            self.details.show_process(record)

    def _on_select(self) -> None:
        """Fires when the selection model changes (keyboard nav, programmatic select)."""
        items = self.table.selectedItems()
        if not items:
            self.details.clear()
            return
        self._show_record_at(items[0].row())

    # ------------------------------------------------------------------ actions
    def _record_at(self, row: int) -> dict[str, Any] | None:
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _on_table_context_menu(self, pos) -> None:
        """Right-click menu over the process table. Same actions as the buttons."""
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        # Make sure the right-clicked row becomes the current row so the
        # details panel and the menu actions agree on what we're acting on.
        self.table.selectRow(index.row())
        record = self._record_at(index.row())
        if not record:
            return
        has_path = bool(record.get("exe"))

        menu = QMenu(self)
        a_locate = menu.addAction("📂  Open file location")
        a_copy = menu.addAction("📋  Copy path")
        a_search = menu.addAction("🔍  Search online")
        a_vt = menu.addAction("🛡  Check on VirusTotal")
        menu.addSeparator()
        a_end = menu.addAction("⨯  End process…")

        a_locate.setEnabled(has_path)
        a_copy.setEnabled(has_path)
        a_vt.setEnabled(has_path)

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is a_locate:   self._action_open_location(record)
        elif chosen is a_copy:   self._action_copy_path(record)
        elif chosen is a_search: self._action_search_online(record)
        elif chosen is a_vt:     self._action_virustotal(record)
        elif chosen is a_end:    self._action_end(record)

    def _action_copy_path(self, record: dict[str, Any]) -> None:
        path = record.get("exe") or ""
        if path:
            QApplication.clipboard().setText(path)
            self.status_label.setText(f"Copied path: {path}")

    def _action_open_location(self, record: dict[str, Any]) -> None:
        path = record.get("exe") or ""
        if not path or not os.path.exists(path):
            self.status_label.setText("Can't open location — file path unavailable.")
            return
        # /select tells Explorer to highlight the file rather than just open the folder.
        try:
            subprocess.Popen(["explorer.exe", f"/select,{path}"])
        except Exception as e:
            self.status_label.setText(f"Failed to open Explorer: {e}")

    def _action_search_online(self, record: dict[str, Any]) -> None:
        name = record.get("name", "")
        exe = record.get("exe", "")
        # Use the immediate parent folder as a search hint — that's usually
        # what gives away what product the binary belongs to.
        folder = os.path.basename(os.path.dirname(exe)) if exe else ""
        query = " ".join(filter(None, [f'"{name}"', f'"{folder}"' if folder else ""])).strip()
        url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
        QDesktopServices.openUrl(QUrl(url))

    def _action_virustotal(self, record: dict[str, Any]) -> None:
        path = record.get("exe") or ""
        if not path or not os.path.isfile(path):
            self.status_label.setText("Can't check on VirusTotal — file path unavailable.")
            return
        try:
            self.status_label.setText("Computing SHA-256 hash…")
            QApplication.processEvents()
            sha = self._sha256(path)
        except Exception as e:
            self.status_label.setText(f"Couldn't read file: {e}")
            return
        # VirusTotal's hash-lookup URL doesn't upload the file; if nobody has
        # ever uploaded the same file, the page will say "not found" without
        # exposing the user's binary.
        url = f"https://www.virustotal.com/gui/file/{sha}"
        QDesktopServices.openUrl(QUrl(url))
        self.status_label.setText(f"Opened VirusTotal for SHA-256 {sha[:16]}…")

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()

    def _action_end(self, record: dict[str, Any]) -> None:
        name = record.get("name", "?")
        pid = record.get("pid")
        if not pid:
            return
        db = (record["assessment"].get("db_entry") or {})
        is_critical = db.get("trust") == "trusted" and db.get("category") == "Windows Core"

        # Build a confirmation message scaled to how dangerous this is.
        if is_critical:
            msg = (
                f"<b>{name}</b> is a critical Windows process.<br><br>"
                "Ending it will almost certainly crash Windows or force a reboot. "
                "Are you absolutely sure?"
            )
            icon = QMessageBox.Icon.Critical
        else:
            msg = (
                f"End <b>{name}</b> (PID {pid})?<br><br>"
                "Anything that depends on it will stop until the process is restarted."
            )
            icon = QMessageBox.Icon.Question

        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle("End process")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(msg)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        # Try the friendly route first: terminate via psutil. Falls back to
        # an elevated taskkill if Windows refuses for permission reasons.
        try:
            psutil.Process(pid).kill()
            self.status_label.setText(f"Ended {name} (PID {pid}).")
            # Drop the row from the table so the user sees something happened.
            self._records = [r for r in self._records if r["pid"] != pid]
            self._refresh_table()
            return
        except psutil.NoSuchProcess:
            self.status_label.setText(f"{name} (PID {pid}) had already exited.")
            self._records = [r for r in self._records if r["pid"] != pid]
            self._refresh_table()
            return
        except psutil.AccessDenied:
            pass  # fall through to elevated retry
        except Exception as e:
            self.status_label.setText(f"Couldn't end {name}: {e}")
            return

        # Elevated retry — pop a UAC prompt and run taskkill as admin. This
        # is much less disruptive than relaunching the whole app elevated.
        reply = QMessageBox.question(
            self,
            "Administrator permission needed",
            f"Ending <b>{name}</b> requires administrator permission. "
            f"Show the UAC prompt and retry?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "taskkill.exe", f"/F /PID {pid}", None, 0
            )
            if ret <= 32:  # ShellExecuteW returns an HINSTANCE > 32 on success
                self.status_label.setText("UAC cancelled or elevation failed.")
                return
            self.status_label.setText(f"Sent elevated kill request for {name} (PID {pid}).")
        except Exception as e:
            self.status_label.setText(f"Elevated kill failed: {e}")


# ---------------------------------------------------------------- main
def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(AUTHOR)
    app.setStyleSheet(STYLESHEET)

    # Single-instance guard. If the user double-clicks the .exe twice (or has
    # it pinned to the taskbar and clicks again), the second launch detects
    # the first via a named shared-memory segment and exits politely instead
    # of running a duplicate scan in a duplicate window.
    #
    # The shared-memory handle is stashed on the app so it lives for the
    # full lifetime of the process. Windows automatically releases the
    # segment when the last handle closes, including on crash — no leftover
    # locks survive a kill.
    _instance_guard = QSharedMemory(f"{APP_NAME}-singleton-v1-{AUTHOR}")
    if not _instance_guard.create(1):
        QMessageBox.information(
            None,
            APP_NAME,
            f"{APP_NAME} is already running.<br><br>"
            f"Look for the existing window in your taskbar.",
        )
        return 0
    app._instance_guard = _instance_guard  # type: ignore[attr-defined]

    # Force dark palette so any unstyled bits inherit sensible colors.
    pal = app.palette()
    pal.setColor(QPalette.ColorRole.Window, QColor(BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(SURFACE))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(SURFACE_HI))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(SURFACE))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("white"))
    app.setPalette(pal)

    QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont)

    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
