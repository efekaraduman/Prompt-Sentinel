@echo off
REM Set your API key via environment variable before running, or leave unset for open dev mode.
REM Example: set PROMPTSENTINEL_API_KEY=your-secret-key
app\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
