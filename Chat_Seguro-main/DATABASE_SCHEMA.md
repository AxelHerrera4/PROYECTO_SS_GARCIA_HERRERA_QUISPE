# 🗄️ Esquema de Base de Datos - ChatApp

## Índice
- [Diagrama Entidad-Relación](#diagrama-entidad-relación)
- [Colecciones MongoDB](#colecciones-mongodb)
- [Relaciones](#relaciones)
- [Índices](#índices)
- [Consultas Comunes](#consultas-comunes)

---

## Diagrama Entidad-Relación

```
┌─────────────────────────────────────────────────────────────────┐
│                        MongoDB Collections                       │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│       admins         │
├──────────────────────┤
│ _id: ObjectId  [PK]  │◄──────────────────┐
│ username: String     │                    │
│ password: String     │                    │ createdBy (ref)
│ email: String        │                    │
│ fullName: String     │                    │
│ createdAt: Date      │                    │
└──────────────────────┘                    │
                                            │
                                            │
┌──────────────────────┐                   │
│       rooms          │                   │
├──────────────────────┤                   │
│ _id: ObjectId  [PK]  │───────────────────┘
│ name: String         │
│ type: String         │  ('texto' | 'multimedia')
│ pin: String (4)      │  [UNIQUE]
│ createdBy: ObjectId  │  [FK → admins._id]
│ createdAt: Date      │
└──────────────────────┘
         │
         │ 1:N
         │
         ▼
┌──────────────────────┐
│      messages        │
├──────────────────────┤
│ _id: ObjectId  [PK]  │
│ content: String      │  (puede estar vacío si hay file)
│ sender: String       │  (nickname del usuario)
│ roomId: ObjectId     │  [FK → rooms._id]
│ fileUrl: String?     │  (opcional, ruta del archivo)
│ isEdited: Boolean    │  (default: false)
│ createdAt: Date      │
│ updatedAt: Date      │
└──────────────────────┘


┌──────────────────────┐
│       users          │
├──────────────────────┤
│ _id: ObjectId  [PK]  │
│ nickname: String     │
│ roomId: ObjectId     │  [FK → rooms._id]
│ joinedAt: Date       │
└──────────────────────┘
         ▲
         │
         └─────────────┐
                       │ 1:1 (temporal, en sesión)
                       │
               ┌───────────────┐
               │  userSessions │  (En Memoria, NO en DB)
               ├───────────────┤
               │ nickname: {   │
               │   socketId,   │
               │   roomId,     │
               │   lastActivity│
               │ }             │
               └───────────────┘
```

---

## Colecciones MongoDB

### 1. `admins` Collection

Almacena información de administradores que pueden crear y gestionar salas.

```javascript
{
  _id: ObjectId("507f1f77bcf86cd799439011"),
  username: "admin123",
  password: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",  // bcrypt hash
  email: "admin@example.com",
  fullName: "Juan Pérez",
  createdAt: ISODate("2024-01-15T10:30:00Z")
}
```

**Campos:**
- `_id`: Identificador único (MongoDB ObjectId)
- `username`: Nombre de usuario único para login
- `password`: Contraseña hasheada con bcrypt (salt rounds: 10)
- `email`: Email único del administrador
- `fullName`: Nombre completo del administrador
- `createdAt`: Fecha de creación de la cuenta

**Restricciones:**
- `username`: Unique index
- `email`: Unique index
- `password`: Mínimo 6 caracteres (validado en backend)

---

### 2. `rooms` Collection

Almacena las salas de chat creadas por administradores.

```javascript
{
  _id: ObjectId("507f191e810c19729de860ea"),
  name: "Sala de Desarrollo",
  type: "multimedia",  // 'texto' | 'multimedia'
  pin: "1234",  // 4 dígitos únicos
  createdBy: ObjectId("507f1f77bcf86cd799439011"),  // ref → admins._id
  createdAt: ISODate("2024-01-20T14:00:00Z")
}
```

**Campos:**
- `_id`: Identificador único de la sala
- `name`: Nombre descriptivo de la sala
- `type`: Tipo de sala
  - `"texto"`: Solo mensajes de texto
  - `"multimedia"`: Texto + archivos (imágenes, videos, docs)
- `pin`: PIN de 4 dígitos para acceder (generado automáticamente o personalizado)
- `createdBy`: ObjectId que referencia al admin que creó la sala
- `createdAt`: Fecha de creación

**Restricciones:**
- `pin`: Unique index (no puede haber dos salas con el mismo PIN)
- `type`: Enum ['texto', 'multimedia']
- `name`: Requerido, no vacío

---

### 3. `messages` Collection

Almacena todos los mensajes enviados en las salas.

```javascript
{
  _id: ObjectId("507f1f77bcf86cd799439012"),
  content: "¡Hola a todos! 👋",
  sender: "usuario123",  // nickname
  roomId: ObjectId("507f191e810c19729de860ea"),  // ref → rooms._id
  fileUrl: null,  // o "/api/files/imagen_1234567890.png"
  isEdited: false,
  createdAt: ISODate("2024-01-20T15:30:00Z"),
  updatedAt: ISODate("2024-01-20T15:30:00Z")
}
```

**Ejemplo con archivo:**
```javascript
{
  _id: ObjectId("507f1f77bcf86cd799439013"),
  content: "",  // vacío porque es solo un archivo
  sender: "usuario456",
  roomId: ObjectId("507f191e810c19729de860ea"),
  fileUrl: "/api/files/documento_1706194800000.pdf",
  isEdited: false,
  createdAt: ISODate("2024-01-20T15:35:00Z"),
  updatedAt: ISODate("2024-01-20T15:35:00Z")
}
```

**Campos:**
- `_id`: Identificador único del mensaje
- `content`: Contenido de texto (puede estar vacío si solo hay archivo)
- `sender`: Nickname del usuario que envió el mensaje
- `roomId`: ObjectId de la sala donde se envió
- `fileUrl`: Ruta del archivo subido (null si no hay archivo)
- `isEdited`: Indica si el mensaje fue editado (solo texto)
- `createdAt`: Fecha de envío original
- `updatedAt`: Fecha de última edición (Mongoose timestamps)

**Restricciones:**
- `sender` y `roomId`: Requeridos
- Al menos uno de `content` o `fileUrl` debe tener valor
- Solo se puede editar `content` (no `fileUrl`)

---

### 4. `users` Collection

Almacena usuarios que han entrado a salas (historial).

```javascript
{
  _id: ObjectId("507f1f77bcf86cd799439014"),
  nickname: "usuario123",
  roomId: ObjectId("507f191e810c19729de860ea"),
  joinedAt: ISODate("2024-01-20T15:00:00Z")
}
```

**Campos:**
- `_id`: Identificador único del registro
- `nickname`: Nombre que usa el usuario en esa sala
- `roomId`: Sala a la que se unió
- `joinedAt`: Fecha/hora de ingreso

**Notas:**
- Esta colección es principalmente para historial
- Los nicknames son únicos **por sala** (validado en backend)
- No hay contraseña: acceso anónimo con solo nickname + PIN

---

## Relaciones

### Relación: `admins` ↔ `rooms` (1:N)

Un administrador puede crear múltiples salas, pero cada sala tiene un único creador.

```javascript
// Mongoose Population
const room = await Room.findById(roomId).populate('createdBy');
// room.createdBy → { _id, username, email, fullName }
```

**Query ejemplo:**
```javascript
// Obtener todas las salas de un admin
const adminRooms = await Room.find({ createdBy: adminId });
```

---

### Relación: `rooms` ↔ `messages` (1:N)

Una sala puede tener múltiples mensajes, pero cada mensaje pertenece a una única sala.

```javascript
// Obtener todos los mensajes de una sala
const messages = await Message.find({ roomId })
  .sort({ createdAt: 1 })  // Ordenar por fecha ascendente
  .limit(100);  // Últimos 100 mensajes
```

---

### Relación: `rooms` ↔ `users` (1:N)

Una sala puede tener múltiples usuarios activos, pero cada entrada está asociada a una sala.

```javascript
// Obtener usuarios activos en una sala (desde Socket.IO)
const socketsInRoom = await io.in(roomId).fetchSockets();
const activeUsers = socketsInRoom.map(s => s.nickname);
```

**Nota:** La lista de usuarios activos se gestiona principalmente en **memoria** (Socket.IO rooms), no en MongoDB.

---

## Índices

### Índices Existentes (Mongoose Automático)

```javascript
// admins
admins.createIndex({ username: 1 }, { unique: true });
admins.createIndex({ email: 1 }, { unique: true });

// rooms
rooms.createIndex({ pin: 1 }, { unique: true });
rooms.createIndex({ createdBy: 1 });

// messages
messages.createIndex({ roomId: 1 });
messages.createIndex({ createdAt: -1 });

// users
users.createIndex({ roomId: 1 });
```

### Índices Recomendados para Producción

```javascript
// Compound index para búsquedas frecuentes
messages.createIndex({ roomId: 1, createdAt: -1 });

// Para búsqueda de mensajes de un usuario específico
messages.createIndex({ sender: 1, roomId: 1 });

// Para verificar unicidad de nickname por sala
users.createIndex({ nickname: 1, roomId: 1 }, { unique: true });
```

---

## Consultas Comunes

### 1. Obtener Mensajes de una Sala

```javascript
const messages = await Message.find({ roomId: roomId })
  .sort({ createdAt: 1 })
  .limit(100)
  .lean();  // Optimización: retorna objetos planos
```

### 2. Buscar Sala por PIN

```javascript
const room = await Room.findOne({ pin: "1234" });
if (!room) {
  throw new Error('Sala no encontrada');
}
```

### 3. Obtener Salas de un Admin

```javascript
const adminRooms = await Room.find({ createdBy: adminId })
  .sort({ createdAt: -1 })
  .lean();
```

### 4. Crear Mensaje

```javascript
const newMessage = await Message.create({
  content: "Hola mundo",
  sender: "usuario123",
  roomId: roomId,
  fileUrl: null
});
```

### 5. Editar Mensaje

```javascript
const updatedMessage = await Message.findByIdAndUpdate(
  messageId,
  { 
    content: "Contenido editado",
    isEdited: true 
  },
  { new: true }  // Retorna el documento actualizado
);
```

### 6. Eliminar Mensaje

```javascript
await Message.findByIdAndDelete(messageId);
```

### 7. Verificar si Usuario Existe en Sala

```javascript
const existingUser = await User.findOne({ 
  nickname: nickname, 
  roomId: roomId 
});

if (existingUser) {
  throw new Error('Nickname ya en uso en esta sala');
}
```

### 8. Contar Mensajes de una Sala

```javascript
const messageCount = await Message.countDocuments({ roomId: roomId });
```

### 9. Obtener Últimos 50 Mensajes (Paginación)

```javascript
const messages = await Message.find({ roomId: roomId })
  .sort({ createdAt: -1 })
  .limit(50)
  .skip(page * 50)  // Para paginación
  .lean();

// Invertir para mostrar en orden cronológico
messages.reverse();
```

### 10. Eliminar Todos los Mensajes de una Sala (al borrar sala)

```javascript
await Message.deleteMany({ roomId: roomId });
await User.deleteMany({ roomId: roomId });
await Room.findByIdAndDelete(roomId);
```

---

## Modelos Mongoose

### Admin Model

```javascript
const adminSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    match: /^\S+@\S+\.\S+$/
  },
  fullName: { 
    type: String, 
    required: true,
    trim: true
  }
}, { 
  timestamps: true  // createdAt, updatedAt automáticos
});

// Pre-save hook para hash de contraseña
adminSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

module.exports = mongoose.model('Admin', adminSchema);
```

---

### Room Model

```javascript
const roomSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true,
    trim: true,
    minlength: 1
  },
  type: { 
    type: String, 
    required: true,
    enum: ['texto', 'multimedia'],
    default: 'texto'
  },
  pin: { 
    type: String, 
    required: true, 
    unique: true,
    length: 4,
    match: /^\d{4}$/
  },
  createdBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Admin',
    required: true
  }
}, { 
  timestamps: true 
});

module.exports = mongoose.model('Room', roomSchema);
```

---

### Message Model

```javascript
const messageSchema = new mongoose.Schema({
  content: { 
    type: String, 
    default: ''
  },
  sender: { 
    type: String, 
    required: true,
    trim: true
  },
  roomId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Room',
    required: true,
    index: true
  },
  fileUrl: { 
    type: String, 
    default: null 
  },
  isEdited: { 
    type: Boolean, 
    default: false 
  }
}, { 
  timestamps: true  // createdAt, updatedAt
});

// Validación: al menos content o fileUrl debe existir
messageSchema.pre('validate', function(next) {
  if (!this.content && !this.fileUrl) {
    next(new Error('El mensaje debe tener contenido o archivo'));
  }
  next();
});

module.exports = mongoose.model('Message', messageSchema);
```

---

### User Model

```javascript
const userSchema = new mongoose.Schema({
  nickname: { 
    type: String, 
    required: true,
    trim: true,
    minlength: 2
  },
  roomId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Room',
    required: true
  },
  joinedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Índice compuesto para unicidad por sala
userSchema.index({ nickname: 1, roomId: 1 }, { unique: true });

module.exports = mongoose.model('User', userSchema);
```

---

## Estado en Memoria (No en DB)

Aunque no está en MongoDB, estos objetos son cruciales para la funcionalidad:

### userSessions (En memoria - server.js)

```javascript
const userSessions = {
  "usuario123": {
    socketId: "AbCd1234EfGh5678",
    roomId: "507f191e810c19729de860ea",
    lastActivity: 1706195400000  // timestamp
  },
  "usuario456": {
    socketId: "XyZ9876WxYz5432",
    roomId: "507f191e810c19729de860ea",
    lastActivity: 1706195450000
  }
};
```

**Propósito:**
- Control de sesión única por usuario
- Desconexión por inactividad (5 minutos)
- Heartbeat monitoring

---

### kickedUsers (En memoria - server.js)

```javascript
const kickedUsers = {
  "507f191e810c19729de860ea": ["usuario_expulsado1", "usuario_expulsado2"],
  "507f191e810c19729de860eb": ["troll123"]
};
```

**Propósito:**
- Lista negra de usuarios expulsados por sala
- Prevenir re-ingreso de usuarios problemáticos
- Se resetea al reiniciar el servidor

**Mejora Futura:** Persistir en MongoDB o Redis para mantener entre reinicios.

---

## Migraciones y Seed Data

### Script de Seed (Desarrollo)

```javascript
// scripts/seed.js
const mongoose = require('mongoose');
const Admin = require('./models/Admin');
const Room = require('./models/Room');

async function seed() {
  await mongoose.connect(process.env.MONGODB_URI);
  
  // Crear admin de prueba
  const admin = await Admin.create({
    username: 'admin',
    password: 'admin123',
    email: 'admin@test.com',
    fullName: 'Admin de Prueba'
  });
  
  // Crear salas de prueba
  await Room.create([
    { name: 'General', type: 'texto', pin: '1111', createdBy: admin._id },
    { name: 'Multimedia', type: 'multimedia', pin: '2222', createdBy: admin._id }
  ]);
  
  console.log('✅ Base de datos poblada');
  process.exit(0);
}

seed();
```

---

## Backup y Restore

### Backup de MongoDB

```bash
# Backup completo
mongodump --uri="mongodb://localhost:27017/chatapp" --out=./backup/$(date +%Y%m%d)

# Backup solo una colección
mongodump --db=chatapp --collection=messages --out=./backup/messages
```

### Restore

```bash
# Restaurar backup completo
mongorestore --uri="mongodb://localhost:27017/chatapp" ./backup/20240120/

# Restaurar una colección
mongorestore --db=chatapp --collection=messages ./backup/messages/chatapp/messages.bson
```

---

## Performance Tips

1. **Proyección de Campos**: Solo solicitar campos necesarios
   ```javascript
   const rooms = await Room.find().select('name pin type -_id');
   ```

2. **Lean Queries**: Retornar objetos planos (más rápido)
   ```javascript
   const messages = await Message.find({ roomId }).lean();
   ```

3. **Limitar Resultados**: Usar `.limit()` siempre que sea posible
   ```javascript
   const latestMessages = await Message.find({ roomId }).limit(50);
   ```

4. **Índices**: Crear índices para campos de búsqueda frecuente

5. **Aggregation Pipeline**: Para consultas complejas
   ```javascript
   const stats = await Message.aggregate([
     { $match: { roomId: roomId } },
     { $group: { _id: '$sender', count: { $sum: 1 } } },
     { $sort: { count: -1 } }
   ]);
   ```

---

**Última actualización:** Noviembre 2025
