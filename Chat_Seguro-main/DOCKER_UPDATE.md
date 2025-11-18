# 🔄 Actualización Docker - Node.js 20

## Problema Detectado

Si al ejecutar `docker-compose up` ves este error:

```
You are using Node.js 18.20.8. Vite requires Node.js version 20.19+ or 22.12+.
TypeError: crypto.hash is not a function
```

**Causa:** La nueva versión de Vite requiere Node.js 20+ pero las imágenes Docker usaban Node.js 18.

## ✅ Solución

Los Dockerfiles ya están actualizados a `node:20-alpine` y la configuración está arreglada. Si descargaste el proyecto antes del 10/11/2025, sigue estos pasos:

### 1. Actualiza el repositorio

```bash
git pull origin main
```

### 2. Elimina las imágenes antiguas

```bash
# Detener contenedores
docker-compose down

# Eliminar imágenes antiguas (con Node 18)
docker rmi chatapp-frontend chatapp-backend

# O eliminar todo (más limpio)
docker system prune -a
```

### 3. Reconstruye y reinicia

**Windows:**
```bash
docker-start.bat
```

**Linux/Mac:**
```bash
chmod +x docker-start.sh
./docker-start.sh
```

**O manualmente:**
```bash
# Reconstruir desde cero
docker-compose build --no-cache

# Iniciar
docker-compose up
```

## 🎯 Verificación

Deberías ver:

```
chatapp-backend  | 🚀 Servidor en http://localhost:5000
chatapp-backend  | Conectado a MongoDB
chatapp-frontend | VITE v6.x.x  ready in xxx ms
chatapp-frontend | ➜  Local:   http://localhost:5173/
```

## 📝 Cambios Realizados

- **Frontend Dockerfile:** `node:18-alpine` → `node:20-alpine`
- **Backend Dockerfile:** `node:18-alpine` → `node:20-alpine` (por consistencia)
- **docker-compose.yml:** Sin cambios (usa los Dockerfiles actualizados)

## ❓ Preguntas Frecuentes

### ¿Por qué Node 20?

Vite (el bundler del frontend) agregó una nueva función `crypto.hash` que solo existe en Node.js 20+.

### ¿Afecta mi instalación local?

No. Si ejecutas el proyecto sin Docker, verifica tu versión de Node:

```bash
node --version
```

Si es menor a v20.19, actualiza desde: https://nodejs.org

### ¿El backend también necesitaba actualización?

No era obligatorio, pero se actualizó para mantener consistencia y aprovechar mejoras de Node 20.

## 🆘 Problemas Persistentes

### Error: `ERR_CONNECTION_REFUSED` o `Failed to connect to ws://localhost:4000`

**Causa:** El frontend está intentando conectarse al puerto incorrecto o el backend no está corriendo.

**Solución:**

1. Verifica que el backend esté corriendo:
   ```bash
   docker-compose ps
   ```
   Deberías ver `chatapp-backend` en estado `Up`

2. Verifica los logs del backend:
   ```bash
   docker-compose logs backend
   ```
   Debes ver: `🚀 Servidor en http://localhost:5000` y `Conectado a MongoDB`

3. Si el error persiste, reconstruye sin caché:
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up
   ```

### Limpieza completa (último recurso)

Si el error continúa:

```bash
# Limpiar TODO (contenedores, imágenes, volúmenes, cache)
docker-compose down -v
docker system prune -a --volumes
docker builder prune -a

# Reconstruir completamente
docker-compose build --no-cache
docker-compose up
```

---

**Última actualización:** 10/11/2025  
**Versión Docker:** Node 20-alpine
