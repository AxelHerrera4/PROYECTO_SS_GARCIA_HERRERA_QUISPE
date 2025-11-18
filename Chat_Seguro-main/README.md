# 💬 ChatApp - Aplicación de Chat en Tiempo Real

Sistema de chat con salas, mensajes en tiempo real, panel de administración y seguridad avanzada.

---

## 🚀 Inicio Rápido con Docker (RECOMENDADO)

### 📥 Para descargar y usar este proyecto

#### 1️⃣ Clonar desde GitHub
```bash
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp
```

**Alternativa sin Git:** Descarga el ZIP desde https://github.com/cjgranda19/chatapp → Botón "Code" → "Download ZIP"

#### 2️⃣ Iniciar con Docker

**Windows:**
```cmd
Doble clic en INICIAR.bat
```
O desde terminal:
```cmd
.\INICIAR.bat
```

**Linux/Mac:**
```bash
chmod +x INICIAR.sh
./INICIAR.sh
```

⏳ **Espera 2-3 minutos** la primera vez (descarga dependencias)

#### 3️⃣ Acceder a la aplicación

El navegador se abre automáticamente en:
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000

#### 4️⃣ Login como Admin

- **Usuario**: `admin`
- **Contraseña**: `admin`

✅ El admin se crea automáticamente en MongoDB al iniciar.

---

## 📋 Requisitos

- **Git** (para clonar): https://git-scm.com/downloads
- **Docker Desktop** (Windows/Mac): https://www.docker.com/products/docker-desktop
- **Docker Engine** (Linux): `sudo apt install docker.io docker-compose`

**📖 Guía completa de descarga:** Ver [COMO_DESCARGAR.md](COMO_DESCARGAR.md)

---
## 🛠️ Comandos Útiles

```bash
# Ver logs en tiempo real
docker-compose logs -f

# Ver logs solo del backend
docker-compose logs -f backend

# Detener la aplicación
docker-compose down

# Reiniciar servicios
docker-compose restart

# Reconstruir desde cero
docker-compose down -v
docker-compose up --build
```

---

## 🏗️ Arquitectura

```
┌─────────────────┐
│   Frontend      │  React + Vite + Socket.IO Client
│   Port: 5173    │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│   Backend       │  Node.js + Express + Socket.IO
│   Port: 5000    │  + AES-256 Encryption
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│   MongoDB       │  Base de datos
│   Port: 27017   │
└─────────────────┘
```

---

## 🔐 Seguridad Implementada

- ✅ **Encriptación AES-256-CBC** para mensajes
- ✅ **JWT con 128 caracteres** criptográficamente seguros
- ✅ **Logging seguro** (oculta datos sensibles)
- ✅ **Detección de esteganografía** en archivos
- ✅ **Validación de archivos corruptos**
- ✅ **Docker con Node 22-alpine** (sin CVEs)
- ✅ **Helmet + CORS** configurado
- ✅ **Validación de entrada** con express-validator

---
                             │
                    ─────────┼─────────
                    WebSocket│HTTP/REST
                    ─────────┼─────────
                             │
┌────────────────────────────▼───────────────────────────────┐
│                   BACKEND (Node.js + Express)               │
│  ┌────────────────────────────────────────────────────┐   │
│  │              Socket.IO Server                       │   │
│  │  • Rooms management  • Real-time messaging          │   │
│  │  • User sessions     • Activity monitoring          │   │
│  └────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌────────────────────────┴────────────────────────────┐  │
│  │                   REST API                            │  │
│  │  /api/auth     /api/rooms     /api/messages          │  │
│  │  /api/admin    /api/files     /api/users             │  │
│  └───────────────────────────────────────────────────────┘ │
│                            │                                │
│  ┌────────────────────────┴────────────────────────────┐  │
│  │              Middleware & Services                    │  │
│  │  • JWT Auth    • Multer Upload   • PIN Generator     │  │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────────────┬───────────────────────────────┘
                             │
                    ─────────┼─────────
                             │
┌────────────────────────────▼───────────────────────────────┐
│                    MongoDB Database                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Users   │  │  Rooms   │  │ Messages │  │  Admins  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    File Storage (Local)                      │
│                      /uploads directory                      │
└─────────────────────────────────────────────────────────────┘
```

### Flujo de Datos

1. **Autenticación**: Cliente → REST API → MongoDB → JWT Token
2. **Creación de Sala**: Admin → REST API → MongoDB → Socket.IO Broadcast
3. **Mensaje en Tiempo Real**: Cliente → Socket.IO → MongoDB → Broadcast a Sala
4. **Subida de Archivo**: Cliente → Multer Middleware → File Storage → Socket.IO Broadcast

---

## 📦 Requisitos Previos

Antes de instalar, asegúrate de tener:

- **Node.js**: v18.0 o superior ([Descargar](https://nodejs.org/))
- **MongoDB**: v6.0 o superior ([Descargar](https://www.mongodb.com/try/download/community))
  - Puede ser local o MongoDB Atlas
- **npm**: v9.0 o superior (incluido con Node.js)
- **Git**: Para clonar el repositorio

### Verificar instalaciones:

```bash
node --version   # Debería mostrar v18.x.x o superior
npm --version    # Debería mostrar v9.x.x o superior
mongo --version  # Debería mostrar v6.x.x o superior
```

---

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/chatapp.git
cd chatapp
```

### 2. Instalar dependencias del Backend

```bash
cd backend
npm install
```

**Dependencias principales:**
- `express` - Framework web
- `socket.io` - WebSockets en tiempo real
- `mongoose` - ODM para MongoDB
- `jsonwebtoken` - Autenticación JWT
- `bcryptjs` - Hash de contraseñas
- `multer` - Subida de archivos
- `cors` - Configuración CORS
- `dotenv` - Variables de entorno

### 3. Instalar dependencias del Frontend

```bash
cd ../frontend
npm install
```

**Dependencias principales:**
- `react` - Framework UI
- `react-dom` - Renderizado de React
- `vite` - Build tool y dev server
- `socket.io-client` - Cliente WebSocket
- `axios` - Cliente HTTP
- `react-hot-toast` - Notificaciones toast

---

## ⚙️ Configuración

### Backend - Variables de Entorno

Crea un archivo `.env` en la carpeta `backend/`:

```env
# Servidor
PORT=4000
NODE_ENV=development

# Base de datos MongoDB
MONGODB_URI=mongodb://localhost:27017/chatapp
# O si usas MongoDB Atlas:
# MONGODB_URI=mongodb+srv://usuario:password@cluster.mongodb.net/chatapp

# JWT Secret (generar uno seguro)
JWT_SECRET=tu_secreto_super_seguro_aqui_cambiar_en_produccion

# CORS - URL del frontend
CLIENT_ORIGIN=http://localhost:5173
```

**🔐 Generar JWT_SECRET seguro:**

```bash
# En terminal:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Frontend - Configuración API

Edita `frontend/src/api/config.js`:

```javascript
export const API_URL = "http://localhost:4000";
```

**Para producción**, cambia a tu URL de backend desplegado.

---

## ▶️ Ejecución

### Opción 1: Desarrollo (modo watch)

**Terminal 1 - Backend:**
```bash
cd backend
npm run dev
```
Servidor corriendo en: `http://localhost:4000`

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```
Frontend corriendo en: `http://localhost:5173` (o 5174)

### Opción 2: Producción

**Backend:**
```bash
cd backend
npm start
```

**Frontend:**
```bash
cd frontend
npm run build
npm run preview
```

---

## 📖 Uso

### 1. Registro de Administrador

1. Abre el frontend en tu navegador
2. Click en **"Crear cuenta"**
3. Completa el formulario:
   - Nombre completo
   - Usuario (único)
   - Email (único)
   - Contraseña (mínimo 6 caracteres)
4. Click en **"Registrarse"**

### 2. Crear una Sala

1. Inicia sesión con tu cuenta
2. En el Dashboard, ve a **"Crear nueva sala"**
3. Completa:
   - **Nombre** de la sala
   - **Tipo**: Texto o Multimedia
   - **PIN** (opcional, se genera automáticamente)
4. Click en **"Crear Sala"**
5. Se generará un PIN de 4 dígitos

### 3. Unirse a una Sala

1. Comparte el **PIN de 4 dígitos** con otros usuarios
2. Los usuarios ingresan:
   - **PIN** de la sala
   - **Nickname** (único en la sala)
3. Click en **"Unirse"**

### 4. Chat en Tiempo Real

**Enviar mensajes:**
- Escribe en el input inferior
- Presiona **Enter** o click en **"Enviar"**

**Subir archivos** (solo salas multimedia):
- Click en el ícono **📎**
- Selecciona archivo (máx 50MB)
- El archivo se comparte automáticamente

**Editar mensaje:**
- Click derecho en tu mensaje
- Selecciona **"Editar mensaje"**
- Modifica el texto
- Click en ✓ o presiona Enter

**Eliminar mensaje:**
- Click derecho en mensaje (tuyo o si eres admin)
- Selecciona **"Eliminar mensaje"**
- Confirma la acción

### 5. Gestión de Sala (Admin)

**Ver participantes:**
- Click en **"👥 Participantes"**
- Lista de usuarios conectados

**Expulsar usuario:**
- En lista de participantes
- Click en **🚫** junto al usuario
- Confirma la expulsión
- El usuario no podrá reingresar

**Editar/Eliminar sala:**
- Ve a **"Mis salas creadas"**
- Click en **"Editar"** para cambiar nombre/tipo
- Click en **"Eliminar"** para borrar sala permanentemente

---

## 🛠️ Tecnologías

### Backend
- **Node.js** (v18+) - Runtime de JavaScript
- **Express.js** - Framework web minimalista
- **Socket.IO** - WebSockets bidireccionales
- **MongoDB** - Base de datos NoSQL
- **Mongoose** - ODM para MongoDB
- **JWT (jsonwebtoken)** - Autenticación stateless
- **bcryptjs** - Hash de contraseñas
- **Multer** - Middleware para subida de archivos
- **CORS** - Cross-Origin Resource Sharing
- **dotenv** - Gestión de variables de entorno

### Frontend
- **React** (v18.3) - Biblioteca UI
- **Vite** - Build tool moderno
- **Socket.IO Client** - Cliente WebSocket
- **Axios** - Cliente HTTP
- **React Hot Toast** - Sistema de notificaciones
- **CSS3** - Estilos personalizados (sin frameworks)

### Base de Datos
- **MongoDB** - Almacenamiento de datos
  - Colecciones: Users, Admins, Rooms, Messages, UserRooms

### Herramientas de Desarrollo
- **Nodemon** - Auto-restart del servidor
- **ESLint** - Linter de código
- **Git** - Control de versiones

---

## 📁 Estructura del Proyecto

```
chatapp/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   ├── db.js              # Configuración MongoDB
│   │   │   └── multer.js          # Configuración subida archivos
│   │   ├── controllers/
│   │   │   ├── adminController.js # Lógica de administradores
│   │   │   ├── authController.js  # Autenticación
│   │   │   ├── fileController.js  # Subida de archivos
│   │   │   ├── messageController.js # CRUD mensajes
│   │   │   ├── roomController.js  # CRUD salas
│   │   │   └── userController.js  # Gestión usuarios
│   │   ├── middleware/
│   │   │   └── authMiddleware.js  # Middleware JWT
│   │   ├── models/
│   │   │   ├── Admin.js           # Modelo Admin
│   │   │   ├── Message.js         # Modelo Mensaje
│   │   │   ├── Room.js            # Modelo Sala
│   │   │   ├── User.js            # Modelo Usuario
│   │   │   └── UserRoom.js        # Relación User-Room
│   │   ├── routes/
│   │   │   ├── adminRoutes.js     # Rutas admin
│   │   │   ├── authRoutes.js      # Rutas autenticación
│   │   │   ├── fileRoutes.js      # Rutas archivos
│   │   │   ├── messageRoutes.js   # Rutas mensajes
│   │   │   ├── roomRoutes.js      # Rutas salas
│   │   │   └── userRoutes.js      # Rutas usuarios
│   │   ├── utils/
│   │   │   ├── jwt.js             # Utilidades JWT
│   │   │   └── pinGenerator.js    # Generador de PINs
│   │   ├── app.js                 # Configuración Express
│   │   └── server.js              # Servidor Socket.IO
│   ├── uploads/                   # Archivos subidos
│   ├── .env                       # Variables de entorno
│   ├── package.json
│   └── README.md
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── config.js          # Configuración API
│   │   │   └── socket.js          # Cliente Socket.IO
│   │   ├── components/
│   │   │   ├── AdminLogin.jsx     # Login admin
│   │   │   ├── AdminPanel.jsx     # Panel gestión salas
│   │   │   ├── AdminPanel.css
│   │   │   ├── ChatRoom.jsx       # Sala de chat
│   │   │   ├── ChatRoom.css
│   │   │   ├── Dashboard.jsx      # Panel principal
│   │   │   ├── Dashboard.css
│   │   │   ├── Login.jsx          # Login usuario
│   │   │   ├── Login.css
│   │   │   ├── Register.jsx       # Registro
│   │   │   └── RoomMessages.jsx   # Mensajes sala
│   │   ├── App.jsx                # Componente principal
│   │   ├── App.css
│   │   ├── main.jsx               # Punto de entrada
│   │   └── index.css              # Estilos globales
│   ├── public/                    # Assets estáticos
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── README.md
│
├── TESTING_SESSION.md             # Guía de pruebas
├── README.md                      # Este archivo
└── .gitignore
```

---

## 📊 Diagramas

### Diagrama de Secuencia: Autenticación

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend
    participant B as Backend
    participant DB as MongoDB

    U->>F: Ingresa credenciales
    F->>B: POST /api/auth/login
    B->>DB: Buscar usuario
    DB-->>B: Usuario encontrado
    B->>B: Validar contraseña (bcrypt)
    B->>B: Generar JWT token
    B-->>F: Token + datos usuario
    F->>F: Guardar token en localStorage
    F-->>U: Redirigir a Dashboard
```

### Diagrama de Secuencia: Creación de Sala

```mermaid
sequenceDiagram
    participant A as Admin
    participant F as Frontend
    participant B as Backend
    participant DB as MongoDB
    participant S as Socket.IO

    A->>F: Click "Crear Sala"
    A->>F: Ingresa nombre y tipo
    F->>B: POST /api/rooms (con JWT)
    B->>B: Validar JWT token
    B->>B: Generar PIN único (4 dígitos)
    B->>DB: Guardar sala
    DB-->>B: Sala creada con ID
    B->>S: Broadcast nuevo sala
    S-->>F: Actualizar lista de salas
    B-->>F: Respuesta exitosa
    F-->>A: Mostrar PIN generado
```

### Diagrama de Secuencia: Mensaje en Tiempo Real

```mermaid
sequenceDiagram
    participant U1 as Usuario 1
    participant F1 as Frontend 1
    participant S as Socket.IO Server
    participant DB as MongoDB
    participant F2 as Frontend 2
    participant U2 as Usuario 2

    U1->>F1: Escribe mensaje
    F1->>S: emit('sendMessage')
    S->>S: Actualizar lastActivity
    S->>DB: Guardar mensaje
    DB-->>S: Mensaje guardado con ID
    S->>S: Broadcast a sala
    S-->>F1: emit('newMessage')
    S-->>F2: emit('newMessage')
    F1-->>U1: Mostrar mensaje (verde)
    F2-->>U2: Mostrar mensaje (blanco)
```

### Diagrama de Arquitectura de Componentes

```
┌─────────────────────────────────────────────────────┐
│                   CAPA DE PRESENTACIÓN               │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐      │
│  │  Login/   │  │ Dashboard │  │ ChatRoom  │      │
│  │ Register  │  │           │  │           │      │
│  └───────────┘  └───────────┘  └───────────┘      │
│       │               │               │             │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐      │
│  │AdminLogin │  │AdminPanel │  │Components │      │
│  └───────────┘  └───────────┘  └───────────┘      │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│                  CAPA DE SERVICIOS                   │
│  ┌──────────────────┐  ┌──────────────────┐        │
│  │  Socket.IO Client│  │  Axios (HTTP)    │        │
│  └──────────────────┘  └──────────────────┘        │
└─────────────────────────────────────────────────────┘
                        │
          ──────────────┼──────────────
                WebSocket/HTTP
          ──────────────┼──────────────
                        │
┌─────────────────────────────────────────────────────┐
│                   CAPA DE LÓGICA                     │
│  ┌──────────────────────────────────────┐          │
│  │         Socket.IO Server              │          │
│  │  • joinRoom    • sendMessage          │          │
│  │  • kickUser    • userActivity         │          │
│  └──────────────────────────────────────┘          │
│  ┌──────────────────────────────────────┐          │
│  │           REST API Routes             │          │
│  │  /auth  /rooms  /messages  /files     │          │
│  └──────────────────────────────────────┘          │
│  ┌──────────────────────────────────────┐          │
│  │            Controllers                │          │
│  │  auth • room • message • file         │          │
│  └──────────────────────────────────────┘          │
│  ┌──────────────────────────────────────┐          │
│  │            Middleware                 │          │
│  │  JWT Auth • Multer • CORS             │          │
│  └──────────────────────────────────────┘          │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│                 CAPA DE PERSISTENCIA                 │
│  ┌──────────────────────────────────────┐          │
│  │            Mongoose ODM               │          │
│  └──────────────────────────────────────┘          │
│  ┌──────────────────────────────────────┐          │
│  │         MongoDB Database              │          │
│  │  Users • Rooms • Messages • Admins    │          │
│  └──────────────────────────────────────┘          │
│  ┌──────────────────────────────────────┐          │
│  │        File Storage (uploads/)        │          │
│  └──────────────────────────────────────┘          │
└─────────────────────────────────────────────────────┘
```

---

## 🔒 Seguridad

### Implementaciones de Seguridad

1. **Autenticación JWT**
   - Tokens con expiración de 7 días
   - Almacenados en localStorage (frontend)
   - Validados en cada request protegido

2. **Encriptación de Contraseñas**
   - Bcrypt con salt rounds
   - Hash antes de guardar en DB
   - Comparación segura en login

3. **Sesión Única**
   - Un usuario = una conexión activa
   - Desconexión automática de sesiones anteriores
   - Previene uso simultáneo de cuentas

4. **Validación de Entradas**
   - Validación de tipos de archivo
   - Límite de tamaño (50MB)
   - Sanitización de PINs y nicknames

5. **CORS Configurado**
   - Solo permite origen del frontend
   - Métodos HTTP específicos
   - Credentials habilitados

6. **Lista Negra de Expulsados**
   - Usuarios expulsados no pueden reingresar
   - Control por sala
   - Persistente durante sesión del servidor

### Recomendaciones para Producción

- [ ] Usar HTTPS (TLS/SSL)
- [ ] JWT_SECRET fuerte y único
- [ ] Rate limiting en endpoints
- [ ] Validación adicional de inputs
- [ ] Logs de auditoría
- [ ] Backups regulares de MongoDB
- [ ] Monitoreo de recursos del servidor
- [ ] Variables de entorno en servidor seguro

---

## 🧪 Pruebas

### Pruebas Automáticas (Backend)

El proyecto incluye **22 test cases** con **67% de cobertura** de código.

```bash
# Backend - Ejecutar todos los tests
cd backend
npm test

# Ver cobertura detallada
npm run test:coverage

# Tests en modo watch
npm run test:watch
```

**Tests implementados:**
- ✅ `pinGenerator.test.js` - Generación de PINs (4 tests)
- ✅ `jwt.test.js` - Utilidades JWT (11 tests)
- ✅ `authRoutes.test.js` - Rutas de autenticación (7 tests)
- ✅ `roomRoutes.test.js` - CRUD de salas (2 tests)

**Cobertura por módulo:**
- Utils: ~87%
- Auth Controller: ~95%
- Auth Routes: 100%
- Models: ~68%
- Global: ~67% ✅

**Documentación completa:** Ver `backend/TESTING.md` y `backend/TEST_SUMMARY.md`

### Pruebas Manuales

Consulta el archivo `TESTING_SESSION.md` para guías detalladas de:
- Sesión única por dispositivo
- Desconexión por inactividad
- Expulsión de usuarios
- Subida de archivos
- Mensajería en tiempo real
cd frontend
npm test
```

**Nota:** Las pruebas unitarias están en desarrollo. Se planea alcanzar 70%+ de cobertura.

### Cobertura Objetivo

- [ ] Autenticación (login, register, JWT)
- [ ] CRUD de salas
- [ ] Envío de mensajes
- [ ] Subida de archivos
- [ ] Validaciones de entrada
- [ ] Middleware de autenticación
- [ ] Socket.IO eventos

---

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Si deseas colaborar:

1. **Fork** el repositorio
2. Crea una **rama** para tu feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. **Push** a la rama (`git push origin feature/AmazingFeature`)
5. Abre un **Pull Request**

### Lineamientos

- Código limpio y comentado
- Seguir convenciones de estilo existentes
- Incluir pruebas para nuevas funcionalidades
- Actualizar documentación si es necesario

---

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo `LICENSE` para más detalles.

---

## 👥 Autores

- Carlos - Erick - Desarrollo inicial

---

## 🙏 Agradecimientos

- Comunidad de Node.js
- Equipo de Socket.IO
- MongoDB University
- React Team
- Todos los contribuidores

---

## 📈 Roadmap

### Versión Actual: 1.0.0

### Próximas Versiones

**v1.1.0** (Corto plazo)
- [ ] Pruebas unitarias completas (70%+ cobertura)
- [ ] Deployment con Docker
- [ ] CI/CD con GitHub Actions
- [ ] Modo oscuro

**v1.2.0** (Mediano plazo)
- [ ] Notificaciones push
- [ ] Búsqueda de mensajes
- [ ] Historial de mensajes paginado
- [ ] Reacciones a mensajes (emoji)
- [ ] Mensajes de voz

**v2.0.0** (Largo plazo)
- [ ] Videollamadas WebRTC
- [ ] Encriptación end-to-end
- [ ] Aplicación móvil (React Native)
- [ ] Temas personalizables
- [ ] Bots y webhooks

---

## 🐛 Problemas Conocidos

- La lista negra de usuarios expulsados se resetea al reiniciar el servidor
  - **Solución planificada**: Persistir en MongoDB
- Los archivos subidos no tienen versionado
  - **Solución planificada**: Implementar versionado con timestamps

---



---

**Desarrollado por El grupo de nosotros XD usando Node.js y React**
