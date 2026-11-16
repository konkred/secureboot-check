@echo off
REM Update ueber Windows anstossen (BitLocker wird fuer 3 Neustarts angehalten)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootCheck.ps1" -Apply -Force
