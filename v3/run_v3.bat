@echo off
setlocal EnableExtensions

set "V3_DIR=%~dp0"
for %%I in ("%V3_DIR%..") do set "REPO_ROOT=%%~fI"
cd /d "%V3_DIR%"

set "VENV_ACTIVATE=%REPO_ROOT%\.venv\Scripts\activate.bat"
set "HAS_VENV=0"

if exist "%VENV_ACTIVATE%" (
  set "HAS_VENV=1"
  echo Found .venv. It will be activated in each window.
) else (
  echo .venv not found. Using system Python.
)

if exist "%V3_DIR%requirements.txt" (
  echo Installing requirements from requirements.txt...
  if "%HAS_VENV%"=="1" (
    call "%VENV_ACTIVATE%"
    python -m pip install -r "%V3_DIR%requirements.txt"
  ) else (
    python -m pip install -r "%V3_DIR%requirements.txt"
  )
) else (
  echo No requirements.txt found. Skipping install step.
)

if "%HAS_VENV%"=="1" (
  start "VA-Connect v3 Watchdog" cmd /k "cd /d ""%V3_DIR%"" && call ""%VENV_ACTIVATE%"" && echo Starting watchdog... && python -m va_watchdog.watchdog"
) else (
  start "VA-Connect v3 Watchdog" cmd /k "cd /d ""%V3_DIR%"" && echo Starting watchdog... && python -m va_watchdog.watchdog"
)

echo.
echo Launched the v3 watchdog window.
echo Close that window to stop v3 local testing.
pause
