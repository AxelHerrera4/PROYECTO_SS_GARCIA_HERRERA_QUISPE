@echo off
chcp 65001 > nul
cls
echo.
echo ============================================
echo   🚀 ChatApp - Inicio Rápido con Docker
echo ============================================
echo.

REM Verificar si Docker está corriendo
docker info > nul 2>&1
if errorlevel 1 (
    echo ❌ Docker no está corriendo
    echo.
    echo Por favor inicia Docker Desktop y vuelve a ejecutar este script.
    echo.
    pause
    exit /b 1
)

echo ✅ Docker está corriendo
echo.

REM Detener contenedores previos si existen
echo 🧹 Limpiando contenedores anteriores...
docker-compose down > nul 2>&1

echo.
echo 📦 Construyendo e iniciando contenedores...
echo    (Esto puede tardar 2-3 minutos la primera vez)
echo.

docker-compose up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Error al iniciar contenedores
    echo.
    echo Intenta ejecutar:
    echo    docker-compose down -v
    echo    docker-compose up --build
    echo.
    pause
    exit /b 1
)

echo.
echo ⏳ Esperando que los servicios estén listos...
timeout /t 5 /nobreak > nul

echo.
echo ============================================
echo   ✅ Aplicación iniciada correctamente
echo ============================================
echo.
echo 📍 Acceso:
echo    Frontend:  http://localhost:5173
echo    Backend:   http://localhost:5000
echo    MongoDB:   localhost:27017
echo.
echo 👤 Credenciales admin:
echo    Usuario:   admin
echo    Password:  admin
echo.
echo 📊 Ver logs:       docker-compose logs -f
echo 🛑 Detener:        docker-compose down
echo 🔄 Reiniciar:      docker-compose restart
echo.
echo ============================================
echo.

REM Abrir navegador automáticamente
echo 🌐 Abriendo navegador...
start http://localhost:5173

echo.
echo Presiona cualquier tecla para salir (los contenedores seguirán corriendo)
pause > nul
