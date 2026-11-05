@echo off
REM Build the proxy steam_api64.dll with MSVC (Visual Studio Build Tools).
REM Run this from a "x64 Native Tools Command Prompt for VS".
cl /nologo /LD /O2 /EHsc /MT /std:c++17 dllmain.cpp /link /DEF:steam_api64.def /OUT:steam_api64.dll
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo.
echo Built steam_api64.dll - see README.md for installation.
