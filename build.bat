@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo   NetScan GUI v2.1 - сборка Windows EXE
echo ============================================

where python >nul 2>nul
if errorlevel 1 (echo [ОШИБКА] Python не найден в PATH.& pause & exit /b 1)

if not exist venv (
    echo [1/4] Создаю venv...
    python -m venv venv || goto :err
)
echo [2/4] Активирую venv...
call venv\Scripts\activate.bat

echo [3/4] Устанавливаю зависимости (2-4 минуты)...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt || goto :err

echo [4/4] Собираю EXE...
pyinstaller --clean --noconfirm NetScanGUI.spec || goto :err

echo.
echo ============================================
echo   ГОТОВО: dist\NetScanGUI.exe
echo ============================================
pause & exit /b 0

:err
echo [ОШИБКА] Сборка прервана.
pause & exit /b 1