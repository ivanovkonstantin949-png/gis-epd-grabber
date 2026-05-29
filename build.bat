@echo off
echo === GIS EPD Grabber Build ===
echo.

REM Установка зависимостей
pip install -r requirements.txt

REM Сборка .exe
pyinstaller ^
  --onefile ^
  --name "GisEpdGrabber" ^
  --console ^
  --hidden-import cryptography ^
  --hidden-import httpx ^
  grabber.py

echo.
echo === Build done! ===
echo EXE: dist\GisEpdGrabber.exe
pause
