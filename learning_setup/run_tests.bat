@echo off
REM Quick Test Runner for SQL Injection Learning
echo.
echo ===================================================
echo   SQL Injection Scanner - Learning Tests
echo ===================================================
echo.
echo This will test your scanner against the vulnerable app.
echo Make sure the vulnerable app is running first!
echo.
echo Press any key to start testing...
pause >nul

REM Run the test script
python test_scanner.py

echo.
echo ===================================================
echo   Testing Complete!
echo ===================================================
echo.
echo Check your results above and read the learning guide.
echo.
pause