@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv || exit /b 1
  .venv\Scripts\python.exe -m pip install --upgrade pip || exit /b 1
  .venv\Scripts\python.exe -m pip install -r requirements.txt || exit /b 1
)
if not exist .env (
  echo ERROR: Copy .env.example to .env and configure AEGIS_TOKEN first.
  exit /b 2
)
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8787
