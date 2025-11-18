#!/bin/bash

# Script de inicio para Docker
# Este script configura automáticamente el entorno Docker

echo "🐳 Iniciando ChatApp con Docker..."
echo ""

# Verificar si Docker está corriendo
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker no está corriendo"
    echo "   Por favor, inicia Docker Desktop y vuelve a intentar"
    exit 1
fi

# Verificar si existe .env en la raíz
if [ ! -f .env ]; then
    echo "📝 Creando archivo .env desde .env.docker.example..."
    cp .env.docker.example .env
    echo "✅ Archivo .env creado"
else
    echo "✅ Archivo .env ya existe"
fi

# Verificar si existe .env en backend
if [ ! -f backend/.env ]; then
    echo "📝 Creando backend/.env desde backend/.env.example..."
    cp backend/.env.example backend/.env
    echo "✅ Archivo backend/.env creado"
else
    echo "✅ Archivo backend/.env ya existe"
fi

# Verificar si existe .env en frontend
if [ ! -f frontend/.env ]; then
    echo "📝 Creando frontend/.env desde frontend/.env.example..."
    cp frontend/.env.example frontend/.env
    echo "✅ Archivo frontend/.env creado"
else
    echo "✅ Archivo frontend/.env ya existe"
fi

echo ""
echo "🔨 Construyendo contenedores (primera vez puede tardar)..."
docker-compose build

echo ""
echo "🚀 Iniciando servicios..."
docker-compose up

# Nota: Para detener: Ctrl+C o docker-compose down
