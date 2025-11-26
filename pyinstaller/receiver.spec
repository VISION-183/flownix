# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['../receiver.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['threading', 'signal', 'queue', 'websockets.sync.server', 'traceback', 'argparse', 'sqlite3', 'socket', 'sys', 'os', 'ssl', 'json', 'pathlib', 'copy'],
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
    name='receiver',
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
