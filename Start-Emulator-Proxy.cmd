@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Start-AndroidWithProxyBridge.ps1"
if errorlevel 1 pause
