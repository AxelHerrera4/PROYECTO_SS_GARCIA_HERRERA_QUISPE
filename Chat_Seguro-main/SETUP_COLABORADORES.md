# 🚀 Guía de Instalación para Colaboradores

Esta guía te ayudará a instalar y ejecutar el proyecto **ChatApp** en tu máquina local.

---

## 📋 Requisitos Previos

Antes de empezar, asegúrate de tener instalado:

- ✅ **Node.js** (v18 o superior) - [Descargar aquí](https://nodejs.org/)
- ✅ **MongoDB** (v5 o superior) - [Descargar aquí](https://www.mongodb.com/try/download/community)
- ✅ **Git** - [Descargar aquí](https://git-scm.com/downloads)

### Verificar instalaciones:
```bash
node --version    # Debe mostrar v18.x.x o superior
npm --version     # Debe mostrar 9.x.x o superior
git --version     # Debe mostrar cualquier versión
mongod --version  # Debe mostrar v5.x.x o superior
```

---

## 📥 Paso 1: Clonar el Repositorio

```bash
# Clonar el proyecto
git clone https://github.com/cjgranda19/chatapp.git

# Entrar a la carpeta del proyecto
cd chatapp
```

---

## 🔧 Paso 2: Configurar el Backend

### 2.1 Instalar dependencias
```bash
cd backend
npm install
```

### 2.2 Configurar variables de entorno
```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# En Windows PowerShell:
Copy-Item .env.example .env
```

### 2.3 Editar el archivo `.env`
Abre `backend/.env` con cualquier editor y configura:

```env
# MongoDB Connection (mantener igual si MongoDB está en tu PC)
MONGODB_URI=mongodb://localhost:27017/chatapp

# JWT Secret (puedes dejar este o cambiarlo)
JWT_SECRET=mi_clave_secreta_para_desarrollo_2024

# Client Origin (donde corre el frontend)
CLIENT_ORIGIN=http://localhost:5173

# Server Port (puerto del backend)
PORT=5000
```

**✅ Guardar el archivo**

---

## 🎨 Paso 3: Configurar el Frontend

### 3.1 Instalar dependencias
```bash
# Desde la carpeta raíz del proyecto
cd ../frontend
npm install
```

### 3.2 Configurar variables de entorno
```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# En Windows PowerShell:
Copy-Item .env.example .env
```

### 3.3 Editar el archivo `.env`
Abre `frontend/.env` con cualquier editor y configura:

```env
# Backend API URL (donde corre el backend)
VITE_API_URL=http://localhost:5000

# Socket.IO URL (mismo que la API)
VITE_SOCKET_URL=http://localhost:5000
```

**✅ Guardar el archivo**

---

## 🗄️ Paso 4: Iniciar MongoDB

### En Windows:
```bash
# Opción 1: Si instalaste MongoDB como servicio
# Ya debería estar corriendo automáticamente

# Opción 2: Iniciar manualmente
mongod --dbpath "C:\data\db"
```

### En macOS/Linux:
```bash
# Opción 1: Con Homebrew (macOS)
brew services start mongodb-community

# Opción 2: Manualmente
mongod --dbpath /usr/local/var/mongodb
```

### Verificar que MongoDB está corriendo:
```bash
# Conectarse a MongoDB
mongosh

# Si se conecta, escribe:
exit
```

---

## ▶️ Paso 5: Ejecutar la Aplicación

Necesitas **3 terminales** abiertas:

### Terminal 1: MongoDB (si no está como servicio)
```bash
mongod
```
**Deja esta terminal abierta**

### Terminal 2: Backend
```bash
# Desde la carpeta raíz del proyecto
cd backend
npm run dev
```

Deberías ver:
```
✅ MongoDB conectado correctamente
🚀 Servidor escuchando en puerto 5000
✅ Socket.IO funcionando
```
**Deja esta terminal abierta**

### Terminal 3: Frontend
```bash
# Desde la carpeta raíz del proyecto (nueva terminal)
cd frontend
npm run dev
```

Deberías ver:
```
  VITE v5.x.x  ready in XXX ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```
**Deja esta terminal abierta**

---

## 🌐 Paso 6: Abrir la Aplicación

1. Abre tu navegador
2. Ve a: **http://localhost:5173**
3. Deberías ver la pantalla de inicio del ChatApp

---

## ✅ Verificación Rápida

### Checklist de que todo funciona:

- [ ] MongoDB está corriendo (no hay errores)
- [ ] Backend muestra "MongoDB conectado correctamente"
- [ ] Frontend carga en http://localhost:5173
- [ ] Puedes registrar un usuario nuevo
- [ ] Puedes crear una sala de chat
- [ ] Los mensajes se envían en tiempo real

---

## 🧪 Ejecutar Tests (Opcional)

```bash
cd backend
npm test

# Con cobertura
npm run test:coverage
```

Deberías ver:
```
Test Suites: 4 passed, 4 total
Tests:       22 passed, 22 total
```

---

## 🛠️ Comandos Útiles

### Detener la aplicación:
- `Ctrl + C` en cada terminal

### Limpiar y reinstalar dependencias:
```bash
# Backend
cd backend
rm -rf node_modules package-lock.json
npm install

# Frontend
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### Ver logs en tiempo real:
```bash
# Backend ya muestra logs automáticamente con npm run dev
```

---

## ❓ Problemas Comunes

### Error: "ECONNREFUSED" o "MongoDB connection failed"
**Solución:** MongoDB no está corriendo
```bash
# Iniciar MongoDB
mongod
```

### Error: "Port 5000 already in use"
**Solución:** Cambiar el puerto en `backend/.env`
```env
PORT=5001
```
Y actualiza `frontend/.env`:
```env
VITE_API_URL=http://localhost:5001
VITE_SOCKET_URL=http://localhost:5001
```

### Error: "Cannot find module"
**Solución:** Reinstalar dependencias
```bash
cd backend
npm install

cd ../frontend
npm install
```

### La página no carga o está en blanco
**Solución:** 
1. Verifica que el backend esté corriendo
2. Abre la consola del navegador (F12) y revisa errores
3. Verifica las URLs en `frontend/.env`

### Los mensajes no se envían en tiempo real
**Solución:**
1. Revisa que Socket.IO esté conectado (consola del navegador)
2. Verifica `VITE_SOCKET_URL` en `frontend/.env`
3. Reinicia el backend

---

## 📚 Estructura del Proyecto

```
chatapp/
├── backend/           # API REST + Socket.IO
│   ├── src/
│   │   ├── controllers/   # Lógica de negocio
│   │   ├── models/        # Modelos de MongoDB
│   │   ├── routes/        # Rutas de la API
│   │   ├── middleware/    # Autenticación JWT
│   │   └── utils/         # Utilidades
│   ├── __tests__/     # Tests unitarios
│   └── uploads/       # Archivos subidos
│
├── frontend/          # React + Vite
│   └── src/
│       ├── components/    # Componentes React
│       └── api/          # Configuración API
│
└── docs/             # Documentación
```

---

## 📖 Documentación Adicional

- **README.md** - Descripción general del proyecto
- **ARCHITECTURE.md** - Arquitectura del sistema
- **DATABASE_SCHEMA.md** - Esquema de la base de datos
- **SEQUENCE_DIAGRAMS.md** - Diagramas de flujo
- **backend/TESTING.md** - Guía de tests

---

## 🆘 ¿Necesitas Ayuda?

Si tienes problemas:

1. **Revisa esta guía completa** - La mayoría de problemas están cubiertos aquí
2. **Verifica los requisitos** - Node.js, MongoDB, etc.
3. **Revisa los logs** - En las terminales del backend y frontend
4. **Abre un Issue** en GitHub con:
   - Descripción del problema
   - Logs de error
   - Sistema operativo
   - Versiones de Node y MongoDB

---

## 🎯 Siguiente Paso

Una vez que todo funcione, puedes:

1. **Crear un usuario** - Regístrate en la aplicación
2. **Crear una sala** - Prueba crear salas públicas y privadas
3. **Invitar amigos** - Comparte el PIN de la sala
4. **Enviar mensajes** - Prueba la mensajería en tiempo real
5. **Subir archivos** - Comparte imágenes en el chat

---

## ✨ Funcionalidades para Probar

- ✅ Registro e inicio de sesión
- ✅ Crear salas públicas/privadas con PIN
- ✅ Unirse a salas con PIN
- ✅ Chat en tiempo real
- ✅ Subir archivos (imágenes)
- ✅ Editar mensajes
- ✅ Eliminar mensajes
- ✅ Panel de administrador
- ✅ Expulsar usuarios
- ✅ Sesión única por dispositivo
- ✅ Desconexión por inactividad (5 min)

---

**¡Listo para empezar! 🚀**

Si todo funciona correctamente, deberías poder chatear en tiempo real con otros usuarios.
