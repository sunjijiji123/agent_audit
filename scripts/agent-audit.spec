# -*- mode: python ; coding: utf-8 -*-
# ============================================
# PyInstaller 打包配置
# 输出: dist/agent-audit (单文件可执行程序)
# ============================================

import os
import platform

# 项目根目录
project_root = os.getcwd()

# 二进制文件路径（根据架构选择）
arch = platform.machine()
if arch == 'aarch64':
    loader_so = 'ebpf/loader-arm64.so'
else:
    loader_so = 'ebpf/loader.so'

# 如果指定的架构文件不存在，尝试通用名称
if not os.path.exists(loader_so):
    if os.path.exists('ebpf/loader.so'):
        loader_so = 'ebpf/loader.so'
    else:
        print(f"⚠️  Warning: {loader_so} not found!")
        loader_so = None

a = Analysis(
    ['cli/cli.py'],
    pathex=[project_root],
    binaries=[
        # (源路径, 目标目录)
        (loader_so, 'ebpf') if loader_so else None,
    ],
    datas=[
        # 配置文件（可选）
        # ('config.json', '.'),
    ],
    hiddenimports=[
        'argparse',
        'ctypes',
        'ctypes.util',
        'json',
        'os',
        'sys',
        'time',
        'signal',
        'subprocess',
        'pathlib',
        'cli.agent_audit',
        'cli.agent_audit.config',
        'cli.agent_audit.daemon',
        'cli.agent_audit.bpf_loader',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'test',
        'unittest',
        'pydoc',
        'distutils',
        'setuptools',
        'pip',
    ],
    noarchive=False,
)

# 过滤掉 None 值
a.binaries = [x for x in a.binaries if x is not None]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='agent-audit',
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
