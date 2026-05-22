@echo off
echo Compiling fuzzer with SQLite3...
g++ -O2 Fuzzer_OOP_fixed.cpp -o fuzzer.exe -I sqlite3/include -L sqlite3/lib -lsqlite3
if %errorlevel% == 0 (
    echo Compilation successful!
    echo Copying SQLite3 DLL...
    copy sqlite3\lib\sqlite3.dll . >nul 2>&1
    echo Ready to run: fuzzer.exe
) else (
    echo Compilation failed!
)
pause