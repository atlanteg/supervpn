@echo off
:: Install tap0901 (tap-windows6) driver and rename the adapter to "supervpn-tap".
:: Run as Administrator.

:: Always work relative to this script's own directory.
set "HERE=%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run this script as Administrator.
    pause
    exit /b 1
)

echo Installing tap0901 driver...
"%HERE%tap-driver\devcon.exe" install "%HERE%tap-driver\OemVista.inf" tap0901
if %errorlevel% neq 0 (
    echo ERROR: Driver installation failed. See above for details.
    pause
    exit /b 1
)

echo Renaming adapter to "supervpn-tap"...
netsh interface set interface name="TAP-Windows Adapter V9"    newname="supervpn-tap" 2>nul
netsh interface set interface name="TAP-Windows Adapter V9 #2" newname="supervpn-tap" 2>nul

echo.
echo Done. The adapter is named "supervpn-tap".
echo Edit client-alice.toml (or client-bob.toml), then run supervpn-client.exe as Administrator.
pause
