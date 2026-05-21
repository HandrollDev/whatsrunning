# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for WhatsRunning.

Build with:
    pyinstaller --noconfirm whatsrunning.spec

Output: dist/WhatsRunning.exe (single-file, no console, embedded shield icon).
"""

block_cipher = None


a = Analysis(
    ["whatsrunning.py"],
    pathex=[],
    binaries=[],
    datas=[],
    # psutil and pywin32 use lazy / platform-specific imports that PyInstaller's
    # static analysis sometimes misses. List them explicitly to be safe.
    hiddenimports=[
        "psutil",
        "psutil._psutil_windows",
        "win32api",
        "win32con",
        "win32com",
        "pywintypes",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim a few large modules we don't actually use, to shave MB off the
        # final .exe. Safe because whatsrunning doesn't import any of these.
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL.ImageQt",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="WhatsRunning",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # GUI app, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="whatsrunning.ico",
)
