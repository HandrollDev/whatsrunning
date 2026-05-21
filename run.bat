@echo off
REM Launches WhatsRunning without leaving a console window open behind it.
cd /d "%~dp0"
start "" pythonw whatsrunning.py
