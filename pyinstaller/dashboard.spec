# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['../dashboard.py'],
    pathex=[],
    binaries=[],
    datas=[('../assets','assets')],
    hiddenimports=['pandas', 'subprocess', 'sqlite3', 'dash', 'json', 'argparse', 'dash_bootstrap_components', 'pathlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='dashboard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
