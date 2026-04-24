# -*- mode: python ; coding: utf-8 -*-
import os
import platform

project_root = os.getcwd()

arch = platform.machine()
if arch == 'aarch64':
    loader_so = 'ebpf/loader-arm64.so'
    if not os.path.exists(loader_so):
        loader_so = 'ebpf/loader.so'
else:
    loader_so = 'ebpf/loader.so'

if not os.path.exists(loader_so):
    print(f"Warning: {loader_so} not found!")
    loader_so = None

a = Analysis(
    ['cli/cli.py'],
    pathex=[project_root],
    binaries=[
        (loader_so, 'ebpf') if loader_so else None,
    ],
    datas=[
        ('ebpf/audit.bpf.o', 'ebpf'),
    ],
    hiddenimports=[
        'argparse', 'ctypes', 'ctypes.util', 'json', 'os', 'sys',
        'time', 'signal', 'subprocess', 'pathlib',
        'cli.agent_audit', 'cli.agent_audit.config',
        'cli.agent_audit.daemon', 'cli.agent_audit.bpf_loader',
    ],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=[
        'tkinter', 'test', 'unittest', 'pydoc',
        'distutils', 'setuptools', 'pip',
    ],
    noarchive=False,
)

a.binaries = [x for x in a.binaries if x is not None]

pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='agent_audit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
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

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    name='agent_audit',
)
