@echo off
setlocal

REM === GIS EPD Grabber (PowerShell) — установка в Task Scheduler ===
REM Запускать от имени Администратора!

set PS1=%~dp0GisEpdGrabber.ps1
if not exist "%PS1%" (
    echo ОШИБКА: GisEpdGrabber.ps1 не найден!
    pause
    exit /b 1
)

REM Разрешить запуск PowerShell скриптов
powershell -Command "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force"

REM Путь к powershell
set PSEXE=powershell.exe
set PSARGS=-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%PS1%"

REM Удалить старые задачи
schtasks /delete /tn "GisEpdGrabber_1000" /f 2>nul
schtasks /delete /tn "GisEpdGrabber_1200" /f 2>nul

REM 10:00
schtasks /create ^
  /tn "GisEpdGrabber_1000" ^
  /tr "\"%PSEXE%\" %PSARGS%" ^
  /sc daily /st 10:00 ^
  /ru "%USERNAME%" ^
  /rl highest /f

REM 12:00
schtasks /create ^
  /tn "GisEpdGrabber_1200" ^
  /tr "\"%PSEXE%\" %PSARGS%" ^
  /sc daily /st 12:00 ^
  /ru "%USERNAME%" ^
  /rl highest /f

echo.
echo === ГОТОВО! ===
echo Задачи созданы: 10:00 и 12:00 ежедневно
echo Лог: %APPDATA%\GisEpdGrabber\grabber.log
pause
