# 🐳 Guía de Docker - ChatApp

Esta guía te muestra cómo ejecutar el proyecto completo con Docker y Docker Compose.

---

## 🎯 Beneficios de Usar Docker

- ✅ **No necesitas instalar MongoDB** - Todo está en contenedores
- ✅ **Configuración automática** - Un solo comando para iniciar todo
- ✅ **Ambiente consistente** - Funciona igual en todos los sistemas
- ✅ **Fácil de limpiar** - Elimina todo sin dejar rastros

---

## 📋 Requisitos

Solo necesitas:
- ✅ **Docker Desktop** - [Descargar aquí](https://www.docker.com/products/docker-desktop/)
  - Para Windows: Docker Desktop for Windows
  - Para Mac: Docker Desktop for Mac
  - Para Linux: Docker Engine

### Verificar instalación:
```bash
docker --version          # Debe mostrar 20.x o superior
docker-compose --version  # Debe mostrar 2.x o superior
```

---

## 🚀 Opción 1: Solo MongoDB (Más Rápido para Desarrollo)

Si solo quieres MongoDB en Docker y ejecutar backend/frontend localmente:

### 1. Iniciar solo MongoDB
```bash
docker-compose up mongodb -d
```

### 2. Verificar que MongoDB está corriendo
```bash
docker ps
# Deberías ver: chatapp-mongodb
```

### 3. Ejecutar Backend y Frontend localmente
```bash
# Terminal 1 - Backend
cd backend
npm install
npm run dev

# Terminal 2 - Frontend
cd frontend
npm install
npm run dev
```

### 4. Detener MongoDB cuando termines
```bash
docker-compose down
```

---

## 🐋 Opción 2: Todo con Docker (Recomendado)

Levanta MongoDB, Backend y Frontend en contenedores:

### 1. Construir e iniciar todos los servicios
```bash
# Primera vez (construye las imágenes)
docker-compose up --build

# Siguientes veces (más rápido)
docker-compose up
```

### 2. Acceder a la aplicación
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **MongoDB**: localhost:27017

### 3. Ver logs en tiempo real
```bash
# Todos los servicios
docker-compose logs -f

# Solo un servicio
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mongodb
```

### 4. Detener todo
```bash
# Detener pero mantener datos
docker-compose down

# Detener y eliminar datos de MongoDB
docker-compose down -v
```

---

## 🔧 Comandos Útiles

### Iniciar servicios en segundo plano
```bash
docker-compose up -d
```

### Ver estado de los contenedores
```bash
docker-compose ps
```

### Reiniciar un servicio específico
```bash
docker-compose restart backend
docker-compose restart frontend
docker-compose restart mongodb
```

### Entrar a un contenedor
```bash
# Backend
docker exec -it chatapp-backend sh

# MongoDB
docker exec -it chatapp-mongodb mongosh
```

### Ver logs de un servicio
```bash
docker-compose logs backend
docker-compose logs frontend
docker-compose logs mongodb
```

### Reconstruir un servicio
```bash
docker-compose up --build backend
```

### Limpiar todo (contenedores, imágenes, volúmenes)
```bash
docker-compose down -v --rmi all
```

---

## 🛠️ Configuración Avanzada

### Cambiar puertos (si están ocupados)

Edita `docker-compose.yml`:

```yaml
services:
  mongodb:
    ports:
      - "27018:27017"  # Cambiar primer número
  
  backend:
    ports:
      - "5001:5000"    # Cambiar primer número
    environment:
      - PORT=5000      # Mantener este
  
  frontend:
    ports:
      - "5174:5173"    # Cambiar primer número
```

Si cambias el puerto del backend, actualiza también:
```yaml
frontend:
  environment:
    - VITE_API_URL=http://localhost:5001      # Nuevo puerto
    - VITE_SOCKET_URL=http://localhost:5001   # Nuevo puerto
```

### Variables de entorno personalizadas

Crea un archivo `.env` en la raíz:
```bash
cp .env.docker.example .env
```

Edita `.env` con tus valores:
```env
JWT_SECRET=tu_clave_super_secreta
MONGODB_PORT=27017
BACKEND_PORT=5000
FRONTEND_PORT=5173
```

---

## 🧪 Ejecutar Tests en Docker

```bash
# Tests del backend
docker-compose exec backend npm test

# Tests con cobertura
docker-compose exec backend npm run test:coverage
```

---

## 📊 Monitoreo

### Ver recursos usados
```bash
docker stats
```

### Ver espacio usado
```bash
docker system df
```

### Inspeccionar un contenedor
```bash
docker inspect chatapp-backend
docker inspect chatapp-mongodb
```

---

## 🗄️ Base de Datos

### Acceder a MongoDB desde el contenedor
```bash
docker exec -it chatapp-mongodb mongosh

# Dentro de mongosh:
use chatapp
show collections
db.users.find()
exit
```

### Backup de la base de datos
```bash
docker exec chatapp-mongodb mongodump --db chatapp --out /data/backup
docker cp chatapp-mongodb:/data/backup ./mongodb-backup
```

### Restaurar backup
```bash
docker cp ./mongodb-backup chatapp-mongodb:/data/backup
docker exec chatapp-mongodb mongorestore --db chatapp /data/backup/chatapp
```

### Limpiar la base de datos
```bash
docker exec -it chatapp-mongodb mongosh chatapp --eval "db.dropDatabase()"
```

---

## ❓ Problemas Comunes

### Error: "port is already allocated"
**Causa:** El puerto ya está en uso

**Solución:**
```bash
# Windows - Ver qué está usando el puerto 5000
netstat -ano | findstr :5000

# Cambiar el puerto en docker-compose.yml
```

### Error: "Cannot connect to the Docker daemon"
**Causa:** Docker Desktop no está corriendo

**Solución:**
1. Abre Docker Desktop
2. Espera a que inicie completamente
3. Intenta de nuevo

### Los cambios en el código no se reflejan
**Causa:** Los volúmenes no están sincronizados

**Solución:**
```bash
# Reiniciar el servicio
docker-compose restart backend

# O reconstruir
docker-compose up --build backend
```

### Error: "network chatapp-network not found"
**Solución:**
```bash
docker-compose down
docker network prune
docker-compose up
```

### MongoDB no inicia o falla el healthcheck
**Solución:**
```bash
# Ver logs de MongoDB
docker-compose logs mongodb

# Reiniciar MongoDB
docker-compose restart mongodb

# Si persiste, recrear el volumen
docker-compose down -v
docker-compose up
```

### Contenedor sale inmediatamente
**Solución:**
```bash
# Ver por qué falló
docker-compose logs backend

# Revisar sintaxis del Dockerfile
# Verificar que package.json existe
```

---

## 🧹 Limpieza

### Limpiar contenedores detenidos
```bash
docker container prune
```

### Limpiar imágenes no usadas
```bash
docker image prune -a
```

### Limpiar volúmenes no usados
```bash
docker volume prune
```

### Limpiar todo (¡cuidado!)
```bash
docker system prune -a --volumes
```

---

## 🚀 Modo Producción

Para producción, crea un `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
    volumes:
      - mongodb_prod:/data/db

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    restart: always
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://admin:${MONGO_PASSWORD}@mongodb:27017/chatapp?authSource=admin
    ports:
      - "5000:5000"

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    restart: always
    ports:
      - "80:80"

volumes:
  mongodb_prod:
```

Ejecutar en producción:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

---

## 📚 Recursos Adicionales

- [Documentación oficial de Docker](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Best Practices](https://docs.docker.com/develop/dev-best-practices/)

---

## ✅ Checklist de Inicio

- [ ] Docker Desktop instalado y corriendo
- [ ] Repositorio clonado
- [ ] En la carpeta raíz del proyecto
- [ ] Ejecutar: `docker-compose up --build`
- [ ] Esperar a que todo inicie (1-2 minutos)
- [ ] Abrir http://localhost:5173
- [ ] Registrar un usuario y probar

---

## 🎯 Resumen de Comandos Más Usados

```bash
# Iniciar todo
docker-compose up

# Iniciar en segundo plano
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener todo
docker-compose down

# Reiniciar un servicio
docker-compose restart backend

# Reconstruir y reiniciar
docker-compose up --build

# Limpiar todo
docker-compose down -v
```

---

**¡Listo para usar! 🚀**

Con estos comandos puedes levantar toda la aplicación sin instalar nada más que Docker.
