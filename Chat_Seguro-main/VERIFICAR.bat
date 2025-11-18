@echo off
chcp 65001 > nul
cls
echo.
echo ═══════════════════════════════════════════════════════════
echo   📋 VERIFICACIÓN DEL SISTEMA - ChatApp Docker
echo ═══════════════════════════════════════════════════════════
echo.
echo Este script verifica que todo esté funcionando correctamente
echo.
pause
cls

echo.
echo [1/5] Verificando Docker...
echo.

docker --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Docker NO está instalado o NO está corriendo
    echo.
    echo Por favor:
    echo   1. Instala Docker Desktop desde https://www.docker.com/products/docker-desktop
    echo   2. Inicia Docker Desktop
    echo   3. Vuelve a ejecutar este script
    echo.
    pause
    exit /b 1
) else (
    echo ✅ Docker está instalado
)

docker info > nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Desktop NO está corriendo
    echo.
    echo Por favor:
    echo   1. Abre Docker Desktop
    echo   2. Espera a que diga "Docker is running"
    echo   3. Vuelve a ejecutar este script
    echo.
    pause
    exit /b 1
) else (
    echo ✅ Docker Desktop está corriendo
)

echo.
echo [2/5] Verificando contenedores...
echo.

docker-compose ps > nul 2>&1
if errorlevel 1 (
    echo ⚠️  Los contenedores NO están corriendo
    echo.
    echo ¿Deseas iniciarlos ahora? (S/N)
    set /p respuesta=
    if /i "%respuesta%"=="S" (
        echo.
        echo Iniciando contenedores...
        docker-compose up -d --build
        timeout /t 10 /nobreak > nul
        goto verificar_contenedores
    ) else (
        echo.
        echo Para iniciar los contenedores ejecuta: INICIAR.bat
        pause
        exit /b 0
    )
)

:verificar_contenedores
docker-compose ps | findstr "Up" > nul
if errorlevel 1 (
    echo ❌ Los contenedores NO están activos
    echo.
    docker-compose ps
    echo.
    pause
    exit /b 1
) else (
    echo ✅ Contenedores activos:
    docker-compose ps
)

echo.
echo [3/5] Verificando Admin en MongoDB...
echo.

timeout /t 3 /nobreak > nul
docker-compose logs backend | findstr /i "admin" > temp_admin.txt
findstr /i "creado" temp_admin.txt > nul
if errorlevel 1 (
    findstr /i "existe" temp_admin.txt > nul
    if errorlevel 1 (
        echo ⚠️  No se encontró mensaje de admin
        echo.
        echo Revisa los logs manualmente:
        echo   docker-compose logs backend
    ) else (
        echo ✅ Admin ya existía previamente
    )
) else (
    echo ✅ Admin creado correctamente: admin/admin
)
del temp_admin.txt > nul 2>&1

echo.
echo [4/5] Verificando conexión a MongoDB...
echo.

docker-compose logs backend | findstr /i "mongodb" > temp_mongo.txt
findstr /i "conectado" temp_mongo.txt > nul
if errorlevel 1 (
    echo ⚠️  No se confirmó conexión a MongoDB
) else (
    echo ✅ Backend conectado a MongoDB
)
del temp_mongo.txt > nul 2>&1

echo.
echo [5/5] Verificando puertos...
echo.

netstat -an | findstr "5173" > nul
if errorlevel 1 (
    echo ⚠️  Puerto 5173 (Frontend) no está escuchando
) else (
    echo ✅ Puerto 5173 (Frontend) activo
)

netstat -an | findstr "5000" > nul
if errorlevel 1 (
    echo ⚠️  Puerto 5000 (Backend) no está escuchando
) else (
    echo ✅ Puerto 5000 (Backend) activo
)

netstat -an | findstr "27017" > nul
if errorlevel 1 (
    echo ⚠️  Puerto 27017 (MongoDB) no está escuchando
) else (
    echo ✅ Puerto 27017 (MongoDB) activo
)

echo.
echo ═══════════════════════════════════════════════════════════
echo   VERIFICACIÓN COMPLETA
echo ═══════════════════════════════════════════════════════════
echo.
echo 📍 Accesos:
echo    Frontend:  http://localhost:5173
echo    Backend:   http://localhost:5000
echo    MongoDB:   localhost:27017
echo.
echo 👤 Credenciales admin:
echo    Usuario:   admin
echo    Password:  admin
echo.
echo ═══════════════════════════════════════════════════════════
echo.
echo ¿Deseas abrir la aplicación en el navegador? (S/N)
set /p abrir=
if /i "%abrir%"=="S" (
    start http://localhost:5173
    echo.
    echo ✅ Navegador abierto
)

echo.
echo Presiona cualquier tecla para salir...
pause > nul
