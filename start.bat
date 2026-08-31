@echo off
title NetScope — Network Diagnostics
echo.
echo  ===================================
echo   NETSCOPE — Network Diagnostics
echo ===================================
echo.

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Go is not installed or not in PATH.
    echo  Download from: https://go.dev/dl/
    echo.
    pause
    exit /b 1
)

echo  Building NetScope...
go build -o netscope.exe ./cmd/netscope
if %errorlevel% neq 0 (
    echo  BUILD FAILED
    pause
    exit /b 1
)

echo  Build successful!
echo  Starting server on http://localhost:8199
echo.
netscope.exe serve
