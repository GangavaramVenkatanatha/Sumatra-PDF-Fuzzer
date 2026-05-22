@echo off
echo ========================================
echo FUZZER SYSTEM STARTUP
echo ========================================

echo Starting C++ Web Server...
echo Server will be available at: http://localhost:8080
echo.
echo Make sure these files are present:
echo   - fuzzer.exe (your compiled fuzzer)
echo   - SumatraPDF.exe (PDF reader)
echo   - outputs/fuzzing.db (database - will be created)
echo.
echo Press Ctrl+C to stop the server
echo.

server.exe