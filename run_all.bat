@echo off
REM Launch both vulnerable learning apps in separate windows
echo.
echo ===========================================
echo   Start SQLi and XSS Learning Labs
echo ===========================================
echo.

echo Launching SQLi lab...
start "SQLi Lab" cmd /k "cd /d %~dp0\learning_setup && python vulnerable_app.py"

echo Launching XSS lab...
start "XSS Lab" cmd /k "cd /d %~dp0\learning_setup && python vulnerable_xss_app.py"

echo.
echo Both vulnerable labs should now be running in new windows.
echo Use the existing command window to run scanner tests.
echo.
pause