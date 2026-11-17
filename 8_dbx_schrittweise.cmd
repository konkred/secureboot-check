@echo off
REM Sperrliste (dbx) Datei fuer Datei einspielen, kleinste zuerst - fuer Firmwares, die die grosse Liste ablehnen
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootManual.ps1" -Execute -DbxStepwise
