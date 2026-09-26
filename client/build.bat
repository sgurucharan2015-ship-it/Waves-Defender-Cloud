@echo off
setlocal
cd /d "%~dp0"
where cmake >nul 2>nul || (echo ERROR: CMake is not in PATH.& exit /b 1)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 || exit /b 1
cmake --build build --config Release || exit /b 1
echo.
echo Built:
echo   %CD%\build\Release\AegisAV.exe
echo   %CD%\build\Release\AegisAV_UI.exe
