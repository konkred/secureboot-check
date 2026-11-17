@echo off
REM Selbsttest der Skripte mit Testdaten, aendert nichts an der Firmware
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-Tests.ps1"
