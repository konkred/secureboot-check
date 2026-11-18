@echo off
REM Windows-11-Voraussetzungen pruefen (CPU, RAM, Datentraeger, Grafik, TPM, Secure Boot), aendert nichts
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win11Check.ps1"
