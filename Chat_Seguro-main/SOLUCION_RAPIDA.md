# 🔧 SOLUCIÓN RÁPIDA - Error de Conexión Docker

## Problema
El frontend muestra:
```
Failed to load resource: net::ERR_CONNECTION_REFUSED
WebSocket connection to 'ws://localhost:4000/socket.io/' failed
```

## Causa
El código tenía hardcodeado `localhost:4000` pero el backend usa puerto `5000`.

## ✅ YA ESTÁ ARREGLADO
Los archivos ya están corregidos. Solo necesitas reconstruir:

## Pasos para tu PC (donde estás ahora)

### 1. Detener Docker
Presiona `Ctrl+C` en la terminal donde está corriendo `docker-compose up`

### 2. Eliminar contenedores antiguos
```bash
docker-compose down
```

### 3. Eliminar imágenes viejas (opcional pero recomendado)
```bash
docker rmi chatapp-frontend chatapp-backend
```

### 4. Reconstruir con los cambios
```bash
docker-compose build --no-cache
```

### 5. Iniciar de nuevo
```bash
docker-compose up
```

## Verificación
Deberías ver en la terminal:
```
chatapp-backend  | 🚀 Servidor en http://localhost:5000
chatapp-backend  | Conectado a MongoDB
chatapp-frontend | VITE v6.x.x  ready in xxx ms
chatapp-frontend | ➜  Local:   http://localhost:5173/
```

Ahora abre: http://localhost:5173

## 🔍 Si aún no funciona
Verifica los logs del backend:
```bash
docker-compose logs backend
```

Verifica que todos los servicios estén corriendo:
```bash
docker-compose ps
```

Deberías ver 3 contenedores en estado "Up":
- chatapp-mongodb
- chatapp-backend  
- chatapp-frontend

---

## Cambios Realizados (FYI)

1. **frontend/src/api/config.js**
   - Cambió: `localhost:4000` → `localhost:5000`
   - Ahora usa variable de entorno `VITE_API_URL`

2. **frontend/Dockerfile + backend/Dockerfile**
   - Actualizado de Node 18 → Node 20

3. **Scripts de inicio automático**
   - `docker-start.bat` (Windows)
   - `docker-start.sh` (Linux/Mac)

Todos los archivos ya están listos en tu carpeta local.
