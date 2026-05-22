@echo off
echo ========================================
echo COMPILING FUZZER WEB SERVER
echo ========================================

echo Compiling server.cpp...
g++ -O2 server.cpp -o server.exe -I sqlite3/include sqlite3/lib/libsqlite3.a -lws2_32

if %errorlevel% equ 0 (
    echo.
    echo ✅ Server compiled successfully!
    echo.
    echo To run the complete system:
    echo   1. First run: server.exe
    echo   2. Then open: http://localhost:8080
    echo   3. Make sure fuzzer.exe and SumatraPDF.exe are in the same folder
) else (
    echo.
    echo ❌ Server compilation failed!
    echo.
    echo Make sure you have:
    echo   - g++ compiler installed
    echo   - SQLite3 libraries in sqlite3/ folder
    echo   - Winsock2 available
)

pause