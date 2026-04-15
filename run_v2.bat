@echo off
setlocal EnableExtensions

set "ROOT=%~dp0"
cd /d "%ROOT%"

set "VENV_ACTIVATE=%ROOT%.venv\Scripts\activate.bat"
set "HAS_VENV=0"

if exist "%VENV_ACTIVATE%" (
  set "HAS_VENV=1"
  echo Found .venv. It will be activated in each window.
) else (
  echo .venv not found. Using system Python.
)

if exist "%ROOT%requirements.txt" (
  echo Installing requirements from requirements.txt...
  if "%HAS_VENV%"=="1" (
    call "%VENV_ACTIVATE%"
    python -m pip install -r requirements.txt
  ) else (
    python -m pip install -r requirements.txt
  )
) else (
  echo No requirements.txt found. Skipping install step.
)

if "%HAS_VENV%"=="1" (
  start "VA-Connect v2 API" cmd /k "cd /d ""%ROOT%"" && call ""%VENV_ACTIVATE%"" && echo Starting API... && uvicorn tools.ubuntu.web.app:app --reload --port 8000"
  start "VA-Connect v2 Watchdog" cmd /k "cd /d ""%ROOT%"" && call ""%VENV_ACTIVATE%"" && echo Starting watchdog... && python -m tools.ubuntu.runtime.site_watchdog"
) else (
  start "VA-Connect v2 API" cmd /k "cd /d ""%ROOT%"" && echo Starting API... && uvicorn tools.ubuntu.web.app:app --reload --port 8000"
  start "VA-Connect v2 Watchdog" cmd /k "cd /d ""%ROOT%"" && echo Starting watchdog... && python -m tools.ubuntu.runtime.site_watchdog"
)

echo.
echo Launched API and watchdog windows.
echo Close those windows to stop v2 local testing.
pause
