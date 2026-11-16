@echo off
REM ACHTUNG: schreibt Secure-Boot-Zertifikate von Hand (jeder Schritt mit JA bestaetigen)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootManual.ps1" -Execute
