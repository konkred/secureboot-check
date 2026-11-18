@echo off
REM Zertifikate 2023 und Sperrliste von Hand einspielen: zeigt den Plan, schreibt erst nach JA
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootManual.ps1" -Execute
