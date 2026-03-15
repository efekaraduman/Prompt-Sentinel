@echo off
set PROMPTSENTINEL_API_KEY=demo123
cd /d C:\Users\efe\Desktop\proje
app\venv\Scripts\python.exe -m uvicorn app.main:app --port 8765 > uvicorn.log 2> uvicorn.err
