@echo off
title VaultDB - Universal Launch
echo ======================================================================
echo  Launching VaultDB (Universal Cross-Platform Mode)
echo ======================================================================

if exist venv\Scripts\python.exe (
    set "PYTHON_EXE=venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

%PYTHON_EXE% scripts/quickstart.py
pause
