# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
    copy_metadata,
)


datas = []
binaries = []
hiddenimports = []

# requests uses certifi's CA bundle at runtime. PyCryptodome loads several
# native modules dynamically, so make both cases explicit for portable builds.
datas += collect_data_files("certifi")
datas += copy_metadata("certifi")
datas += copy_metadata("requests")
datas += copy_metadata("websocket-client")
binaries += collect_dynamic_libs("Crypto")
hiddenimports += collect_submodules("Crypto")

a = Analysis(
    ["KLive_AllRoom_V5.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "setuptools", "pip"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="KLive_AllRoom_V5_24-7",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="x86_64",
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version="version_info.txt",
)
