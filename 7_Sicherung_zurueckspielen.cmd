@echo off
REM Eine Sicherung (Backups\<PC>\ oder Rebuild\<PC>\Original) zurueck in die Firmware schreiben
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecureBootRebuild.ps1" -Restore
