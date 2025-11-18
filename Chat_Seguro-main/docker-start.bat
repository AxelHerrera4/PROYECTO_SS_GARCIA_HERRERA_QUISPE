@echo off
REM Script de inicio para Docker en Windows
REM Este script configura automáticamente el entorno Docker

echo 🐳 Iniciando ChatApp con Docker...
echo.

REM Verificar si Docker está corriendo
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Docker no está corriendo
    echo    Por favor, inicia Docker Desktop y vuelve a intentar
    pause
    exit /b 1
)

REM Verificar si existe .env en la raíz
if not exist .env (
    echo 📝 Creando archivo .env desde .env.docker.example...
    copy .env.docker.example .env >nul
    echo ✅ Archivo .env creado
) else (
    echo ✅ Archivo .env ya existe
)

REM Verificar si existe .env en backend
if not exist backend\.env (
    echo 📝 Creando backend\.env desde backend\.env.example...
    copy backend\.env.example backend\.env >nul
    echo ✅ Archivo backend\.env creado
) else (
    echo ✅ Archivo backend\.env ya existe
)

REM Verificar si existe .env en frontend
if not exist frontend\.env (
    echo 📝 Creando frontend\.env desde frontend\.env.example...
    copy frontend\.env.example frontend\.env >nul
    echo ✅ Archivo frontend\.env creado
) else (
    echo ✅ Archivo frontend\.env ya existe
)

echo.
echo 🔨 Construyendo contenedores (primera vez puede tardar)...
docker-compose build

echo.
echo 🚀 Iniciando servicios...
docker-compose up

REM Nota: Para detener: Ctrl+C o docker-compose down
