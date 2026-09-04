@echo off
setlocal EnableExtensions
chcp 65001 >nul
title DONG GOI KLIVE EXE
cd /d "%~dp0"

echo [1/4] Kiem tra Python 3.11...
py -3.11 -c "import sys; print(sys.version)" >nul 2>&1
if errorlevel 1 goto :NO_PYTHON

echo [2/4] Tao moi truong dong goi rieng...
if not exist ".build_venv\Scripts\python.exe" (
    py -3.11 -m venv ".build_venv"
    if errorlevel 1 goto :FAILED
)

echo [3/4] Cai thu vien va dong goi mot file EXE...
".build_venv\Scripts\python.exe" -m pip install --disable-pip-version-check --upgrade pip
if errorlevel 1 goto :FAILED
".build_venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-build.txt
if errorlevel 1 goto :FAILED
".build_venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean KLive_AllRoom_V5.spec
if errorlevel 1 goto :FAILED

echo [4/4] Hoan tat...
copy /Y "dist\KLive_AllRoom_V5_24-7.exe" "KLive_AllRoom_V5_24-7.exe" >nul
if errorlevel 1 goto :FAILED
echo.
echo DA TAO XONG: %CD%\KLive_AllRoom_V5_24-7.exe
echo File EXE chay tren Windows 10/11 64-bit, may khac khong can cai Python.
echo.
pause
exit /b 0

:NO_PYTHON
echo.
echo KHONG TIM THAY PYTHON 3.11 64-BIT.
echo Hay cai Python 3.11 64-bit va tich "Add Python to PATH", sau do bam lai file nay.
echo.
pause
exit /b 2

:FAILED
echo.
echo DONG GOI THAT BAI. Hay chup phan loi phia tren de kiem tra.
echo.
pause
exit /b 1
