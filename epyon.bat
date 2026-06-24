@echo off
REM ============================================================================
REM Epyon Windows Launcher
REM ============================================================================
REM This batch file provides a helpful error message for Windows CMD/PowerShell
REM users and guides them to the correct environment (Git Bash or WSL).
REM ============================================================================

echo.
echo ============================================================================
echo    Epyon Security Scanner - Windows Environment Detected
echo ============================================================================
echo.
echo Epyon requires bash to run. Please use one of the following options:
echo.
echo Option 1: Git Bash (Recommended)
echo   - Install: https://git-scm.com/download/win
echo   - Open "Git Bash" from the Start menu
echo   - Navigate to this directory
echo   - Run: ./epyon.sh [target]
echo.
echo Option 2: Windows Subsystem for Linux (WSL)
echo   - Install WSL: wsl --install
echo   - Open your WSL terminal (Ubuntu, Debian, etc.)
echo   - Navigate to this directory
echo   - Run: ./epyon.sh [target]
echo.
echo ============================================================================
echo.
echo Current Directory: %CD%
echo.
echo After installing Git Bash or WSL, run:
echo   cd "%CD%"
echo   ./epyon.sh /path/to/project
echo.
echo For more information, see: README.md (Platform Support section)
echo.
echo ============================================================================
echo.

REM Try to detect Git Bash and offer to launch it
set "GIT_BASH_PATHS=C:\Program Files\Git\bin\bash.exe;C:\Program Files (x86)\Git\bin\bash.exe"

for %%p in ("%GIT_BASH_PATHS:;=" "%") do (
    if exist %%p (
        echo Git Bash detected at: %%p
        echo.
        set /p LAUNCH="Would you like to launch Git Bash now? (Y/N): "
        if /i "%LAUNCH%"=="Y" (
            echo.
            echo Launching Git Bash...
            start "" %%p
            exit /b 0
        )
    )
)

echo.
echo Press any key to exit...
pause >nul
exit /b 1
