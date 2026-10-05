# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
d, b, h = collect_all("PySide6")
datas += d; binaries += b; hiddenimports += h

a = Analysis(
    ["netscan_gui.py"],
    pathex=[], binaries=binaries, datas=datas, hiddenimports=hiddenimports,
    hookspath=[], runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "numpy", "scapy", "networkx",
        "IPython", "jupyter", "pandas", "PIL",
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtQml", "PySide6.QtQuick", "PySide6.Qt3DCore",
        "PySide6.QtMultimedia", "PySide6.QtCharts", "PySide6.QtDataVisualization",
        "PySide6.QtTest", "PySide6.QtSql", "PySide6.QtDesigner",
        "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="NetScanGUI",
    debug=False, strip=False, upx=True,
    console=False,
    disable_windowed_traceback=False,
    uac_admin=True,
)