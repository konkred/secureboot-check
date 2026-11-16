@echo off
REM ACHTUNG: schreibt db-Zertifikate UND die Sperrliste (dbx) von Hand (jeder Schritt mit JA bestaetigen)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootManual.ps1" -Execute -IncludeDbx
