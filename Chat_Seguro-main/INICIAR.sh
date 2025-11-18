#!/bin/bash

clear
echo ""
echo "============================================"
echo "  🚀 ChatApp - Inicio Rápido con Docker"
echo "============================================"
echo ""

# Verificar si Docker está corriendo
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker no está corriendo"
    echo ""
    echo "Por favor inicia Docker y vuelve a ejecutar este script."
    echo ""
    exit 1
fi

echo "✅ Docker está corriendo"
echo ""

# Detener contenedores previos si existen
echo "🧹 Limpiando contenedores anteriores..."
docker-compose down > /dev/null 2>&1

echo ""
echo "📦 Construyendo e iniciando contenedores..."
echo "   (Esto puede tardar 2-3 minutos la primera vez)"
echo ""

docker-compose up --build -d

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Error al iniciar contenedores"
    echo ""
    echo "Intenta ejecutar:"
    echo "   docker-compose down -v"
    echo "   docker-compose up --build"
    echo ""
    exit 1
fi

echo ""
echo "⏳ Esperando que los servicios estén listos..."
sleep 5

echo ""
echo "============================================"
echo "  ✅ Aplicación iniciada correctamente"
echo "============================================"
echo ""
echo "📍 Acceso:"
echo "   Frontend:  http://localhost:5173"
echo "   Backend:   http://localhost:5000"
echo "   MongoDB:   localhost:27017"
echo ""
echo "👤 Credenciales admin:"
echo "   Usuario:   admin"
echo "   Password:  admin"
echo ""
echo "📊 Ver logs:       docker-compose logs -f"
echo "🛑 Detener:        docker-compose down"
echo "🔄 Reiniciar:      docker-compose restart"
echo ""
echo "============================================"
echo ""

# Abrir navegador automáticamente (si está disponible)
if command -v xdg-open > /dev/null; then
    echo "🌐 Abriendo navegador..."
    xdg-open http://localhost:5173 > /dev/null 2>&1 &
elif command -v open > /dev/null; then
    echo "🌐 Abriendo navegador..."
    open http://localhost:5173 > /dev/null 2>&1 &
fi

echo ""
echo "Los contenedores están corriendo en segundo plano"
echo ""
