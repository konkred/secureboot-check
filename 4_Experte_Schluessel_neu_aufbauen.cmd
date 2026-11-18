@echo off
REM EXPERTEN: Schluessel ueber den Setup Mode neu aufbauen (2 Durchlaeufe, siehe LIESMICH)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootRebuild.ps1"
