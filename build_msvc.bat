@echo off
REM Build the proxy steam_api64.dll with MSVC (Visual Studio Build Tools).
REM Run from a "x64 Native Tools Command Prompt for VS".
REM Exports come from the /EXPORT pragmas in forwarders.h - no .def here.
cl /nologo /LD /O2 /EHsc /MT /std:c++17 dllmain.cpp /link /OUT:steam_api64.dll
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo.
echo Built steam_api64.dll - see README.md for installation.
