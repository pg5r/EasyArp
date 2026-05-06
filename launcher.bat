@echo off
setlocal

echo [*] Checking Python...

where python >nul 2>&1
if %errorlevel%==0 (
set PY=python
goto check_files
)

where py >nul 2>&1
if %errorlevel%==0 (
set PY=py
goto check_files
)

echo [FATAL ERROR] Python is not installed or not found in PATH.
pause
exit /b

:check_files
echo [*] Checking project files...

if not exist main.py (
echo [FATAL ERROR] Missing file: main.py
pause
exit /b
)

if not exist requirements.txt (
echo [FATAL ERROR] Missing file: requirements.txt
pause
exit /b
)

if not exist core (
echo [FATAL ERROR] Missing folder: core/
pause
exit /b
)

if not exist core\heart.py (
echo [FATAL ERROR] Missing file: core\heart.py
pause
exit /b
)

if not exist core\sniff.py (
echo [FATAL ERROR] Missing file: core\sniff.py
pause
exit /b
)

if not exist core\selfie.py (
echo [FATAL ERROR] Missing file: core\selfie.py
pause
exit /b
)

echo [✓] All required files found.
goto check_drivers

:check_drivers
echo [*] Checking Npcap / WinPcap...

sc query npcap >nul 2>&1
if %errorlevel%==0 goto install

sc query npf >nul 2>&1
if %errorlevel%==0 goto install

echo [FATAL ERROR] Npcap/WinPcap not found.
echo Please install Npcap from https://npcap.com/
pause
exit /b

:install
echo [*] Using %PY%

echo [*] Installing requirements...
%PY% -m pip install -r requirements.txt

if errorlevel 1 (
echo [FATAL ERROR] Failed to install requirements.
pause
exit /b
)

echo [*] Running main.py...
%PY% main.py

if errorlevel 1 (
echo [FATAL ERROR] Program failed to run.
pause
exit /b
)

echo [✓] Done
pause
endlocal
:: EOF
