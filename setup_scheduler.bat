@echo off
setlocal

echo === GIS EPD Grabber — настройка автозапуска ===
echo.

set EXE=%~dp0GisEpdGrabber.exe
if not exist "%EXE%" (
    echo ОШИБКА: GisEpdGrabber.exe не найден!
    echo Скачайте его из раздела Releases на GitHub
    echo и положите рядом с этим файлом.
    pause
    exit /b 1
)

REM Установить переменные среды для Telegram (опционально)
REM set GIS_TG_TOKEN=ВАШ_ТОКЕН_БОТА
REM set GIS_TG_CHAT=ID_ЧАТА_АНАСТАСИИ

REM Удалить старые задачи
schtasks /delete /tn "GisEpdGrabber_1000" /f 2>nul
schtasks /delete /tn "GisEpdGrabber_1200" /f 2>nul

REM Запуск в 10:00
schtasks /create /tn "GisEpdGrabber_1000" /tr "\"%EXE%\"" /sc daily /st 10:00 /ru "%USERNAME%" /rl highest /f
if errorlevel 1 goto :error

REM Запуск в 12:00
schtasks /create /tn "GisEpdGrabber_1200" /tr "\"%EXE%\"" /sc daily /st 12:00 /ru "%USERNAME%" /rl highest /f
if errorlevel 1 goto :error

echo.
echo === Готово! ===
echo Слоты будут браться автоматически в 10:00 и 12:00.
echo Лог: %APPDATA%\GisEpdGrabber\grabber.log
echo.
echo ВАЖНО: Периодически заходите в eopp.epd-portal.ru
echo        через Яндекс Браузер — чтобы сессия не протухла.
echo.
pause
exit /b 0

:error
echo.
echo ОШИБКА: Запустите bat-файл от имени администратора!
echo (правая кнопка мыши — "Запуск от имени администратора")
pause
exit /b 1
