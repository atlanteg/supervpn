@echo off
:: Install tap0901 (tap-windows6) driver and rename the adapter to "supervpn-tap".
:: Run as Administrator.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run this script as Administrator.
    pause
    exit /b 1
)

echo Installing tap0901 driver...
tap-driver\devcon.exe install tap-driver\OemVista.inf tap0901
if %errorlevel% neq 0 (
    echo ERROR: Driver installation failed.
    pause
    exit /b 1
)

echo Renaming adapter to "supervpn-tap"...
:: devcon installs the adapter with a generic name like "TAP-Windows Adapter V9"
:: Find and rename it.
for /f "tokens=*" %%i in ('tap-driver\devcon.exe find tap0901 ^| findstr "tap0901"') do (
    netsh interface set interface name="TAP-Windows Adapter V9" newname="supervpn-tap" 2>nul
)
netsh interface set interface name="TAP-Windows Adapter V9 #2" newname="supervpn-tap" 2>nul

echo.
echo Done. The adapter is named "supervpn-tap".
echo Edit client.toml, then run supervpn-client.exe as Administrator.
pause
