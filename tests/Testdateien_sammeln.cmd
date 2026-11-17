@echo off
REM Echte Secure-Boot-Dateien dieses PCs fuer die Tests sammeln (nur lesen)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-Fixtures.ps1"
