# 🐳 Instrucciones para usar la App con Docker

## Para tus compañeros de trabajo

### 📋 Prerrequisitos

Asegúrate de tener instalado:
- **Docker Desktop** (Windows/Mac) o **Docker Engine** (Linux)
- **Git** (para clonar el repositorio)

---

## 🚀 Pasos para levantar la aplicación

### 1. Clonar el repositorio

```bash
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp
```

### 2. Levantar los contenedores

**Opción A - Windows (PowerShell/CMD):**
```powershell
docker-compose up --build
```

**Opción B - Linux/Mac:**
```bash
docker-compose up --build
```

**Opción C - Ejecutar en segundo plano:**
```bash
docker-compose up -d --build
```

### 3. Esperar a que todo inicie

El proceso tarda aproximadamente 2-3 minutos. Verás:

```
✅ MongoDB iniciado correctamente
✅ Backend conectado a MongoDB
✅ Admin predeterminado creado: admin/admin
✅ Frontend listo
```

### 4. Acceder a la aplicación

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **MongoDB**: localhost:27017

---

## 👤 Credenciales por defecto

### Admin Panel
- **Usuario**: `admin`
- **Contraseña**: `admin`

El admin se crea automáticamente en MongoDB la primera vez que se inicia el backend.

---

## 🛠️ Comandos útiles

### Ver logs en tiempo real
```bash
docker-compose logs -f
```

### Ver logs solo del backend
```bash
docker-compose logs -f backend
```

### Detener la aplicación
```bash
docker-compose down
```

### Detener y eliminar volúmenes (datos de MongoDB)
```bash
docker-compose down -v
```

### Reiniciar solo un servicio
```bash
docker-compose restart backend
docker-compose restart frontend
docker-compose restart mongodb
```

### Reconstruir sin caché
```bash
docker-compose build --no-cache
docker-compose up
```

---

## 📊 Estructura de contenedores

| Servicio | Puerto | Descripción |
|----------|--------|-------------|
| `mongodb` | 27017 | Base de datos MongoDB |
| `backend` | 5000 | API Node.js + Socket.IO |
| `frontend` | 5173 | Aplicación React (Vite) |

---

## 🔧 Solución de problemas

### Problema: "Puerto ya en uso"

Si algún puerto está ocupado, edita `docker-compose.yml`:

```yaml
ports:
  - "PUERTO_NUEVO:PUERTO_INTERNO"
```

Ejemplos:
- Backend: `"4000:5000"` (acceder en http://localhost:4000)
- Frontend: `"3000:5173"` (acceder en http://localhost:3000)

### Problema: "Cannot connect to MongoDB"

1. Verifica que MongoDB esté saludable:
```bash
docker-compose ps
```

2. Reinicia MongoDB:
```bash
docker-compose restart mongodb
```

### Problema: "Admin no se creó"

1. Verifica logs del backend:
```bash
docker-compose logs backend | grep -i admin
```

2. Reinicia el backend:
```bash
docker-compose restart backend
```

### Problema: Cambios en el código no se reflejan

Los volúmenes están configurados para hot-reload, pero si no funciona:

```bash
docker-compose down
docker-compose up --build
```

---

## 🔐 Seguridad

### Variables de entorno incluidas

El `docker-compose.yml` ya incluye todas las variables necesarias:

- ✅ **JWT_SECRET**: 128 caracteres criptográficamente seguros
- ✅ **ENCRYPTION_KEY**: Clave AES-256 para encriptar mensajes
- ✅ **MONGODB_URI**: Conexión automática entre contenedores
- ✅ **CLIENT_ORIGIN**: CORS configurado correctamente

**NO es necesario crear archivos `.env`** - Docker Compose lo maneja todo.

---

## 📦 Datos persistentes

Los datos de MongoDB se guardan en un volumen Docker llamado `mongodb_data`:

```bash
# Ver volúmenes
docker volume ls

# Eliminar datos (CUIDADO - borra todo)
docker-compose down -v
```

---

## 🎯 Flujo completo de inicio

```bash
# 1. Clonar proyecto
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp

# 2. Levantar todo
docker-compose up --build

# 3. Esperar mensaje de éxito (2-3 minutos)

# 4. Abrir navegador
# - Frontend: http://localhost:5173
# - Admin: Login con admin/admin
```

---

## 🆘 Soporte

Si tienes problemas:

1. Revisa los logs: `docker-compose logs -f`
2. Verifica el estado: `docker-compose ps`
3. Reinicia servicios: `docker-compose restart`
4. Reconstruye desde cero: `docker-compose down -v && docker-compose up --build`

---

## ✅ Checklist para verificar que todo funciona

- [ ] MongoDB está corriendo (`docker-compose ps`)
- [ ] Backend muestra "Admin predeterminado creado"
- [ ] Frontend accesible en http://localhost:5173
- [ ] Puedes registrar un usuario nuevo
- [ ] Puedes crear salas
- [ ] Puedes enviar mensajes
- [ ] Puedes login como admin (admin/admin)
- [ ] Panel de admin muestra salas

---

**Fecha de actualización:** 2025-11-14  
**Versión de Docker Compose:** 3.8  
**Versión de Node:** 22-alpine
