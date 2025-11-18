# 📊 Diagramas de Secuencia - ChatApp

Este documento contiene diagramas de secuencia detallados para los flujos principales del sistema.

## Índice
- [1. Registro de Administrador](#1-registro-de-administrador)
- [2. Login de Administrador](#2-login-de-administrador)
- [3. Creación de Sala](#3-creación-de-sala)
- [4. Usuario Entra a Sala](#4-usuario-entra-a-sala)
- [5. Envío de Mensaje](#5-envío-de-mensaje)
- [6. Edición de Mensaje](#6-edición-de-mensaje)
- [7. Eliminación de Mensaje](#7-eliminación-de-mensaje)
- [8. Subida de Archivo](#8-subida-de-archivo)
- [9. Expulsión de Usuario](#9-expulsión-de-usuario)
- [10. Control de Sesión Única](#10-control-de-sesión-única)
- [11. Desconexión por Inactividad](#11-desconexión-por-inactividad)

---

## 1. Registro de Administrador

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(Register.jsx)
    participant B as Backend<br/>(authController)
    participant DB as MongoDB<br/>(admins)

    U->>F: Click "Crear cuenta"
    U->>F: Ingresa datos del formulario
    Note over U,F: username, email,<br/>password, fullName
    
    F->>F: Validar formato email
    F->>F: Validar password (min 6 chars)
    
    F->>B: POST /api/auth/register
    Note right of F: Body: {<br/>  username,<br/>  email,<br/>  password,<br/>  fullName<br/>}
    
    B->>DB: Buscar admin existente<br/>Admin.findOne({ username })
    
    alt Username ya existe
        DB-->>B: Admin encontrado
        B-->>F: 400 Bad Request<br/>{ error: "Usuario ya existe" }
        F->>F: toast.error()
        F-->>U: Mostrar error
    else Username disponible
        DB-->>B: null (no existe)
        
        B->>B: Hashear password<br/>bcrypt.hash(password, 10)
        
        B->>DB: Crear nuevo admin<br/>Admin.create({ ... })
        DB-->>B: Admin creado con _id
        
        B->>B: Generar JWT token<br/>jwt.sign({ id, username })
        
        B-->>F: 201 Created<br/>{ token, admin: {...} }
        
        F->>F: Guardar token<br/>localStorage.setItem('token')
        F->>F: Guardar admin<br/>localStorage.setItem('admin')
        
        F->>F: toast.success("Registro exitoso")
        F->>F: Redirigir a /dashboard
        
        F-->>U: Dashboard renderizado
    end
```

**Tiempo estimado:** 200-500ms

**Casos de error:**
- Email inválido → 400 Bad Request
- Username duplicado → 400 Bad Request
- Email duplicado → 400 Bad Request
- Password muy corto → 400 Bad Request

---

## 2. Login de Administrador

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(AdminLogin.jsx)
    participant B as Backend<br/>(authController)
    participant DB as MongoDB<br/>(admins)

    U->>F: Click "Iniciar sesión"
    U->>F: Ingresa username + password
    
    F->>B: POST /api/auth/login
    Note right of F: Body: {<br/>  username,<br/>  password<br/>}
    
    B->>DB: Buscar admin<br/>Admin.findOne({ username })
    
    alt Usuario no encontrado
        DB-->>B: null
        B-->>F: 401 Unauthorized<br/>{ error: "Credenciales inválidas" }
        F->>F: toast.error()
        F-->>U: Mostrar error
    else Usuario encontrado
        DB-->>B: Admin { _id, username, password, ... }
        
        B->>B: Comparar password<br/>bcrypt.compare(inputPassword, dbPassword)
        
        alt Password incorrecta
            B-->>F: 401 Unauthorized<br/>{ error: "Credenciales inválidas" }
            F->>F: toast.error()
            F-->>U: Mostrar error
        else Password correcta
            B->>B: Generar JWT token<br/>jwt.sign({ id, username }, secret, { expiresIn: '7d' })
            
            B-->>F: 200 OK<br/>{ token, admin: { id, username, email, fullName } }
            
            F->>F: Guardar token<br/>localStorage.setItem('token', token)
            F->>F: Guardar admin<br/>localStorage.setItem('admin', JSON.stringify(admin))
            
            F->>F: toast.success("Bienvenido!")
            F->>F: Redirigir a /dashboard
            
            F-->>U: Dashboard renderizado
        end
    end
```

**Tiempo estimado:** 150-400ms

**Seguridad:**
- Password nunca se envía en respuesta
- Token expira en 7 días
- bcrypt con 10 salt rounds

---

## 3. Creación de Sala

```mermaid
sequenceDiagram
    participant A as Admin
    participant F as Frontend<br/>(Dashboard.jsx)
    participant B as Backend<br/>(roomController)
    participant DB as MongoDB<br/>(rooms)
    participant S as Socket.IO Server
    participant C as Otros Clientes

    A->>F: Click "Crear nueva sala"
    F->>F: Mostrar formulario modal
    
    A->>F: Ingresa nombre y tipo
    Note over A,F: nombre: "Mi Sala"<br/>tipo: "multimedia"<br/>PIN: (opcional)
    
    F->>B: POST /api/rooms/create
    Note right of F: Headers: {<br/>  Authorization: Bearer <token><br/>}<br/>Body: {<br/>  name,<br/>  type,<br/>  pin? (opcional)<br/>}
    
    B->>B: Middleware: Verificar JWT<br/>authMiddleware(req, res, next)
    
    alt Token inválido/expirado
        B-->>F: 401 Unauthorized
        F->>F: localStorage.clear()
        F->>F: Redirigir a /login
    else Token válido
        B->>B: req.user = decoded (admin info)
        
        alt PIN no proporcionado
            B->>B: Generar PIN aleatorio<br/>pinGenerator.generate()
            Note right of B: PIN: "1234"<br/>(4 dígitos únicos)
        end
        
        B->>DB: Verificar PIN único<br/>Room.findOne({ pin })
        
        alt PIN duplicado
            DB-->>B: Sala con ese PIN existe
            B->>B: Generar nuevo PIN
            B->>DB: Verificar nuevamente
        else PIN disponible
            DB-->>B: null (PIN disponible)
            
            B->>DB: Crear sala<br/>Room.create({<br/>  name, type, pin,<br/>  createdBy: req.user.id<br/>})
            
            DB-->>B: Sala creada con _id
            Note right of DB: {<br/>  _id: "507f...",<br/>  name: "Mi Sala",<br/>  type: "multimedia",<br/>  pin: "1234",<br/>  createdBy: "507f...",<br/>  createdAt: "2024-01-20..."<br/>}
            
            B->>S: io.emit('roomCreated', room)
            Note right of B: Broadcast a todos<br/>los clientes conectados
            
            B-->>F: 201 Created<br/>{ sala creada con PIN }
            
            S-->>C: Event 'roomCreated'<br/>{ room data }
            C->>C: Actualizar lista de salas
            
            F->>F: toast.success("Sala creada")
            F->>F: Mostrar modal con PIN
            Note over F: "Sala creada exitosamente<br/>PIN: 1234"
            
            F->>F: Actualizar lista de salas
            F-->>A: Mostrar nueva sala
        end
    end
```

**Tiempo estimado:** 200-600ms

**Validaciones:**
- JWT requerido
- Nombre no vacío
- Tipo: 'texto' o 'multimedia'
- PIN único de 4 dígitos

---

## 4. Usuario Entra a Sala

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant DB as MongoDB
    participant O as Otros Usuarios<br/>en la Sala

    U->>F: Ingresa PIN + Nickname
    F->>F: Validar formato (PIN: 4 dígitos)
    
    F->>S: socket.emit('joinRoom', {<br/>  nickname, roomId<br/>})
    
    S->>DB: Verificar sala existe<br/>Room.findById(roomId)
    
    alt Sala no existe
        DB-->>S: null
        S-->>F: socket.emit('error', { message: 'Sala no encontrada' })
        F->>F: toast.error()
        F-->>U: Mostrar error
    else Sala existe
        DB-->>S: Room { _id, name, type, ... }
        
        S->>S: Verificar lista negra<br/>if (kickedUsers[roomId]?.includes(nickname))
        
        alt Usuario expulsado
            S-->>F: socket.emit('kicked', { reason: 'expulsado' })
            F->>F: Mostrar overlay "🚫 Has sido expulsado"
            F->>F: setTimeout redirigir a home (3s)
            F-->>U: No puede entrar
        else Usuario permitido
            S->>S: Verificar sesión existente<br/>if (userSessions[nickname])
            
            alt Sesión existente
                S->>S: Obtener socket anterior<br/>const oldSocket = io.sockets.sockets.get(oldSocketId)
                
                S->>S: oldSocket.emit('sessionReplaced')
                S->>S: oldSocket.leave(oldRoomId)
                S->>S: delete userSessions[nickname]
                
                Note over S: Sistema mensaje a sala anterior:<br/>"usuario se desconectó<br/>(sesión desde otro dispositivo)"
            end
            
            S->>S: Registrar nueva sesión<br/>userSessions[nickname] = {<br/>  socketId: socket.id,<br/>  roomId,<br/>  lastActivity: Date.now()<br/>}
            
            S->>S: socket.join(roomId)
            Note right of S: Usuario añadido<br/>a la sala Socket.IO
            
            S->>DB: Buscar mensajes<br/>Message.find({ roomId })<br/>  .sort({ createdAt: 1 })<br/>  .limit(100)
            
            DB-->>S: Array de mensajes [...]
            
            S-->>F: socket.emit('loadMessages', messages)
            Note right of S: Solo al usuario<br/>que entró
            
            F->>F: setMessages(messages)
            F->>F: Renderizar mensajes
            
            S->>DB: Buscar usuarios activos<br/>User.find({ roomId })
            DB-->>S: Array usuarios [...]
            
            S->>S: io.to(roomId).emit('userJoined', {<br/>  nickname, users: [...]<br/>})
            Note right of S: Broadcast a TODOS<br/>en la sala
            
            S-->>O: Event 'userJoined'
            O->>O: Actualizar lista usuarios
            O->>O: Mostrar notificación<br/>"usuario123 entró a la sala"
            
            F->>F: Iniciar heartbeat<br/>setInterval(() => {<br/>  socket.emit('userActivity')<br/>}, 120000)
            
            F-->>U: Chat room renderizado
        end
    end
```

**Tiempo estimado:** 300-800ms

**Validaciones:**
- PIN de 4 dígitos
- Nickname no vacío
- Nickname único en la sala
- Usuario no expulsado

---

## 5. Envío de Mensaje

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant DB as MongoDB<br/>(messages)
    participant O as Otros Usuarios

    U->>F: Escribe mensaje en input
    U->>F: Presiona Enter o click "Enviar"
    
    F->>F: Validar mensaje no vacío
    
    F->>S: socket.emit('sendMessage', {<br/>  roomId,<br/>  nickname,<br/>  content: "Hola a todos!"<br/>})
    
    S->>S: Actualizar actividad<br/>userSessions[nickname].lastActivity = Date.now()
    Note right of S: Resetea contador<br/>de inactividad
    
    S->>DB: Crear mensaje<br/>Message.create({<br/>  content,<br/>  sender: nickname,<br/>  roomId,<br/>  fileUrl: null<br/>})
    
    DB-->>S: Mensaje guardado con _id
    Note right of DB: {<br/>  _id: "507f...",<br/>  content: "Hola a todos!",<br/>  sender: "usuario123",<br/>  roomId: "507f...",<br/>  isEdited: false,<br/>  createdAt: "2024-01-20..."<br/>}
    
    S->>S: io.to(roomId).emit('newMessage', message)
    Note right of S: Broadcast a TODOS<br/>en la sala<br/>(incluyendo emisor)
    
    S-->>F: Event 'newMessage'
    F->>F: setMessages(prev => [...prev, message])
    F->>F: Renderizar mensaje (verde - autor)
    F-->>U: Mensaje visible en chat
    
    S-->>O: Event 'newMessage'
    O->>O: setMessages(prev => [...prev, message])
    O->>O: Renderizar mensaje (blanco - otro)
    Note over O: Diferente estilo<br/>según autor
```

**Tiempo estimado:** 50-200ms (tiempo real)

**Características:**
- Broadcast a todos simultáneamente
- Persistido en DB antes de emitir
- Actualiza lastActivity automáticamente
- Limpieza de input después de enviar

---

## 6. Edición de Mensaje

```mermaid
sequenceDiagram
    participant U as Usuario (Autor)
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant DB as MongoDB<br/>(messages)
    participant O as Otros Usuarios

    U->>F: Click derecho en mensaje propio
    F->>F: Mostrar menú contextual<br/>["Editar", "Eliminar"]
    
    U->>F: Click "Editar"
    F->>F: setEditingMessageId(messageId)
    F->>F: Llenar input con content actual
    F-->>U: Input listo para editar
    
    U->>F: Modifica texto
    U->>F: Presiona Enter o click ✓
    
    F->>F: Validar nuevo contenido no vacío
    
    F->>S: socket.emit('editMessage', {<br/>  messageId,<br/>  newContent: "Mensaje editado"<br/>})
    
    S->>DB: Buscar mensaje<br/>Message.findById(messageId)
    
    alt Mensaje no encontrado
        DB-->>S: null
        S-->>F: socket.emit('error', { message: 'Mensaje no encontrado' })
        F->>F: toast.error()
    else Mensaje encontrado
        DB-->>S: Message { _id, content, sender, ... }
        
        S->>S: Verificar autoría<br/>if (message.sender !== nickname)
        
        alt No es el autor
            S-->>F: socket.emit('error', { message: 'No autorizado' })
            F->>F: toast.error("No puedes editar este mensaje")
        else Es el autor
            S->>S: Verificar que no tenga archivo<br/>if (message.fileUrl)
            
            alt Tiene archivo
                S-->>F: socket.emit('error', { message: 'No se pueden editar archivos' })
                F->>F: toast.error()
            else Solo texto
                S->>DB: Actualizar mensaje<br/>Message.findByIdAndUpdate(messageId, {<br/>  content: newContent,<br/>  isEdited: true<br/>}, { new: true })
                
                DB-->>S: Mensaje actualizado
                Note right of DB: {<br/>  ...,<br/>  content: "Mensaje editado",<br/>  isEdited: true,<br/>  updatedAt: "2024-01-20..."<br/>}
                
                S->>S: io.to(roomId).emit('messageEdited', {<br/>  messageId,<br/>  newContent,<br/>  isEdited: true<br/>})
                Note right of S: Broadcast a TODOS
                
                S-->>F: Event 'messageEdited'
                F->>F: Actualizar mensaje en estado<br/>setMessages(prev => prev.map(m => <br/>  m._id === messageId ? {...m, content: newContent, isEdited: true} : m<br/>))
                F->>F: setEditingMessageId(null)
                F->>F: Limpiar input
                F->>F: toast.success("Mensaje editado")
                F-->>U: Mensaje actualizado con badge "editado"
                
                S-->>O: Event 'messageEdited'
                O->>O: Actualizar mensaje en UI
                O->>O: Mostrar badge "editado"
            end
        end
    end
```

**Tiempo estimado:** 100-300ms

**Restricciones:**
- Solo el autor puede editar
- Solo mensajes de texto (no archivos)
- Badge "editado" visible para todos
- updatedAt timestamp automático

---

## 7. Eliminación de Mensaje

```mermaid
sequenceDiagram
    participant U as Usuario/Admin
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant DB as MongoDB<br/>(messages)
    participant O as Otros Usuarios

    U->>F: Click derecho en mensaje
    F->>F: Mostrar menú contextual
    
    U->>F: Click "Eliminar"
    F->>F: Mostrar modal confirmación<br/>"¿Estás seguro?"
    
    U->>F: Click "Confirmar"
    
    F->>S: socket.emit('deleteMessage', {<br/>  messageId,<br/>  nickname<br/>})
    
    S->>DB: Buscar mensaje<br/>Message.findById(messageId)
    
    alt Mensaje no encontrado
        DB-->>S: null
        S-->>F: socket.emit('error', { message: 'Mensaje no encontrado' })
        F->>F: toast.error()
    else Mensaje encontrado
        DB-->>S: Message { _id, sender, roomId, ... }
        
        S->>DB: Buscar sala<br/>Room.findById(roomId)
        DB-->>S: Room { createdBy, ... }
        
        S->>S: Verificar permisos<br/>isAuthor = (message.sender === nickname)<br/>isAdmin = (room.createdBy === userId)
        
        alt No tiene permisos
            S-->>F: socket.emit('error', { message: 'No autorizado' })
            F->>F: toast.error("No tienes permisos")
        else Tiene permisos (autor o admin)
            S->>DB: Eliminar mensaje<br/>Message.findByIdAndDelete(messageId)
            
            DB-->>S: Mensaje eliminado
            
            S->>S: io.to(roomId).emit('messageDeleted', {<br/>  messageId<br/>})
            Note right of S: Broadcast a TODOS
            
            S-->>F: Event 'messageDeleted'
            F->>F: Eliminar de estado<br/>setMessages(prev => <br/>  prev.filter(m => m._id !== messageId)<br/>)
            F->>F: toast.success("Mensaje eliminado")
            F-->>U: Mensaje desaparece de UI
            
            S-->>O: Event 'messageDeleted'
            O->>O: Eliminar mensaje de UI
            Note over O: Desaparece para<br/>todos simultáneamente
        end
    end
```

**Tiempo estimado:** 150-400ms

**Permisos:**
- Autor: Puede eliminar sus propios mensajes
- Admin de sala: Puede eliminar cualquier mensaje
- Otros: No pueden eliminar

---

## 8. Subida de Archivo

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant API as Backend API<br/>(fileController)
    participant M as Multer Middleware
    participant FS as File System<br/>(/uploads)
    participant S as Socket.IO Server
    participant DB as MongoDB<br/>(messages)
    participant O as Otros Usuarios

    U->>F: Click botón adjuntar 📎
    F->>F: <input type="file" />
    
    U->>F: Seleccionar archivo
    Note over U,F: imagen.png (2.5 MB)
    
    F->>F: Validar tipo de sala<br/>if (roomType !== 'multimedia')
    
    alt Sala de texto
        F->>F: toast.error("Esta sala no permite archivos")
        F-->>U: Error mostrado
    else Sala multimedia
        F->>F: Crear FormData<br/>formData.append('file', file)
        
        F->>API: POST /api/files/upload<br/>Content-Type: multipart/form-data
        
        API->>M: multer.single('file')
        
        M->>M: Validar tamaño<br/>if (fileSize > 50MB)
        
        alt Archivo muy grande
            M-->>F: 400 Bad Request<br/>{ error: 'Archivo muy grande' }
            F->>F: toast.error()
        else Tamaño OK
            M->>M: Validar tipo MIME<br/>Permitidos: image/*, video/*, application/pdf, etc.
            
            alt Tipo no permitido
                M-->>F: 400 Bad Request<br/>{ error: 'Tipo de archivo no permitido' }
                F->>F: toast.error()
            else Tipo permitido
                M->>M: Generar filename único<br/>timestamp + "_" + originalname
                Note right of M: 1706195400000_imagen.png
                
                M->>FS: Guardar archivo<br/>fs.writeFile('/uploads/...')
                FS-->>M: Archivo guardado
                
                M->>API: req.file = { filename, path, ... }
                
                API-->>F: 200 OK<br/>{ fileUrl: '/api/files/1706195400000_imagen.png' }
                
                F->>F: toast.success("Archivo subido")
                
                F->>S: socket.emit('sendMessage', {<br/>  roomId,<br/>  nickname,<br/>  content: '',<br/>  fileUrl: '/api/files/...'<br/>})
                
                S->>S: Actualizar lastActivity
                
                S->>DB: Crear mensaje<br/>Message.create({<br/>  content: '',<br/>  sender: nickname,<br/>  roomId,<br/>  fileUrl<br/>})
                
                DB-->>S: Mensaje guardado
                
                S->>S: io.to(roomId).emit('newMessage', message)
                
                S-->>F: Event 'newMessage'
                F->>F: Renderizar según tipo de archivo
                alt Es imagen
                    F->>F: <img src={fileUrl} />
                else Es video
                    F->>F: <video src={fileUrl} controls />
                else Es PDF
                    F->>F: <a href={fileUrl} download>📄 documento.pdf</a>
                end
                F-->>U: Archivo visible en chat
                
                S-->>O: Event 'newMessage'
                O->>O: Renderizar archivo
            end
        end
    end
```

**Tiempo estimado:** 500ms-5s (depende del tamaño)

**Validaciones:**
- Tamaño máximo: 50MB
- Tipos permitidos:
  - Imágenes: JPG, PNG, GIF, WebP, SVG
  - Videos: MP4, WebM, MOV
  - Docs: PDF, DOC, DOCX, XLS, XLSX
  - Audio: MP3, WAV, OGG
  - Comprimidos: ZIP, RAR, 7Z

---

## 9. Expulsión de Usuario

```mermaid
sequenceDiagram
    participant A as Admin de Sala
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant DB as MongoDB
    participant U as Usuario Expulsado

    A->>F: Click "👥 Participantes"
    F->>F: Mostrar lista de usuarios
    
    A->>F: Click 🚫 junto a usuario
    F->>F: Mostrar confirmación<br/>"¿Expulsar a usuario123?"
    
    A->>F: Click "Confirmar"
    
    F->>S: socket.emit('kickUser', {<br/>  nickname: 'usuario123',<br/>  roomId,<br/>  adminId<br/>})
    
    S->>DB: Verificar permisos<br/>Room.findOne({<br/>  _id: roomId,<br/>  createdBy: adminId<br/>})
    
    alt No es admin de la sala
        DB-->>S: null
        S-->>F: socket.emit('error', { message: 'No autorizado' })
        F->>F: toast.error("Solo el creador puede expulsar")
    else Es admin
        DB-->>S: Room encontrado
        
        S->>S: Añadir a lista negra<br/>if (!kickedUsers[roomId]) {<br/>  kickedUsers[roomId] = []<br/>}<br/>kickedUsers[roomId].push(nickname)
        
        S->>S: Obtener socket del usuario<br/>userSessions[nickname]?.socketId
        
        alt Usuario conectado
            S->>S: const userSocket = io.sockets.sockets.get(socketId)
            
            S->>S: userSocket.emit('kicked', {<br/>  reason: 'admin'<br/>})
            Note right of S: Notificar al usuario<br/>que fue expulsado
            
            S->>S: userSocket.leave(roomId)
            Note right of S: Remover de sala Socket.IO
            
            S->>S: delete userSessions[nickname]
            Note right of S: Limpiar sesión
            
            S-->>U: Event 'kicked'
            U->>U: setIsKicked(true)
            U->>U: setDisconnectReason('expulsado')
            U->>U: Mostrar overlay<br/>"🚫 Has sido expulsado de la sala"
            U->>U: setTimeout(() => navigate('/'), 3000)
            Note over U: Redirige a home<br/>después de 3 segundos
            
            S->>S: io.to(roomId).emit('userLeft', {<br/>  nickname,<br/>  reason: 'kicked'<br/>})
            Note right of S: Notificar a otros<br/>en la sala
            
            S-->>F: Event 'userLeft'
            F->>F: Actualizar lista usuarios
            F->>F: Mostrar notificación<br/>"usuario123 fue expulsado"
            F->>F: toast.success("Usuario expulsado")
            F-->>A: Lista actualizada
        end
    end
```

**Tiempo estimado:** 100-300ms

**Características:**
- Solo el creador de la sala puede expulsar
- Usuario añadido a lista negra (kickedUsers)
- No puede reingresar (validado en joinRoom)
- Lista negra se resetea al reiniciar servidor

**Mejora futura:** Persistir lista negra en MongoDB

---

## 10. Control de Sesión Única

```mermaid
sequenceDiagram
    participant U1 as Usuario<br/>(Dispositivo 1)
    participant F1 as Frontend 1<br/>(Tab/Browser 1)
    participant S as Socket.IO Server
    participant U2 as Usuario<br/>(Dispositivo 2)
    participant F2 as Frontend 2<br/>(Tab/Browser 2)

    Note over U1,F1: Usuario ya conectado<br/>desde dispositivo 1
    
    U1->>F1: En sala activa
    Note over F1: userSessions["usuario123"] = {<br/>  socketId: "AbC123",<br/>  roomId: "507f...",<br/>  lastActivity: 1706195400000<br/>}
    
    U2->>F2: Abre aplicación en otro dispositivo
    U2->>F2: Ingresa mismo nickname + PIN
    
    F2->>S: socket.emit('joinRoom', {<br/>  nickname: 'usuario123',<br/>  roomId<br/>})
    
    S->>S: Verificar sesión existente<br/>if (userSessions["usuario123"])
    
    alt Sesión existente encontrada
        S->>S: Obtener datos sesión anterior<br/>oldSocketId = "AbC123"<br/>oldRoomId = "507f..."
        
        S->>S: const oldSocket = <br/>io.sockets.sockets.get(oldSocketId)
        
        alt Socket anterior existe
            S->>S: oldSocket.emit('sessionReplaced', {<br/>  message: 'Sesión iniciada desde otro dispositivo'<br/>})
            
            S-->>F1: Event 'sessionReplaced'
            F1->>F1: setIsKicked(true)
            F1->>F1: setDisconnectReason('sesión reemplazada')
            F1->>F1: Mostrar overlay<br/>"🔄 Sesión reemplazada por otro dispositivo"
            F1->>F1: socket.disconnect()
            F1->>F1: setTimeout(() => navigate('/'), 3000)
            F1-->>U1: Desconectado, redirigiendo...
            
            S->>S: oldSocket.leave(oldRoomId)
            
            S->>S: io.to(oldRoomId).emit('systemMessage', {<br/>  content: 'usuario123 se desconectó (sesión desde otro dispositivo)'<br/>})
            Note right of S: Notificar a sala anterior
        end
        
        S->>S: delete userSessions["usuario123"]
        Note right of S: Limpiar sesión anterior
    end
    
    S->>S: Registrar nueva sesión<br/>userSessions["usuario123"] = {<br/>  socketId: "XyZ789",<br/>  roomId: roomId,<br/>  lastActivity: Date.now()<br/>}
    
    S->>S: console.log("✅ Sesión registrada para usuario123")
    
    S->>S: socket.join(roomId)
    
    S->>S: Cargar mensajes y usuarios...
    
    S-->>F2: socket.emit('loadMessages', messages)
    S-->>F2: io.to(roomId).emit('userJoined', {...})
    
    F2->>F2: Renderizar chat
    F2->>F2: Iniciar heartbeat
    F2-->>U2: Conectado exitosamente
    
    Note over S: Solo 1 sesión activa<br/>por nickname
```

**Tiempo estimado:** 200-500ms

**Características:**
- Automático: No requiere intervención del usuario
- Desconexión suave del dispositivo anterior
- Mensaje informativo en ambos lados
- Solo una conexión activa por nickname

**Logs del servidor:**
```
🔄 usuario123 reemplazó su sesión anterior
✅ Sesión registrada para usuario123 - Socket: XyZ789 - Sala: 507f...
```

---

## 11. Desconexión por Inactividad

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend<br/>(ChatRoom.jsx)
    participant S as Socket.IO Server
    participant T as Timer (Backend)

    Note over F: Usuario conectado en sala
    
    F->>F: useEffect: Iniciar heartbeat<br/>setInterval(() => {<br/>  socket.emit('userActivity')<br/>}, 120000)
    Note over F: Ping cada 2 minutos
    
    loop Cada 2 minutos
        F->>S: socket.emit('userActivity')
        S->>S: Actualizar timestamp<br/>userSessions[nickname].lastActivity = Date.now()
        Note right of S: Resetea contador<br/>de inactividad
    end
    
    Note over U,F: Usuario deja de interactuar<br/>(cierra laptop, no escribe, etc.)
    
    rect rgb(255, 200, 200)
        Note over F: Heartbeat deja de enviarse<br/>(navegador inactivo)
    end
    
    Note over T: setInterval(() => checkInactivity(), 30000)
    
    loop Cada 30 segundos
        T->>T: Iterar userSessions
        
        T->>T: Para cada usuario:<br/>inactiveTime = Date.now() - lastActivity
        
        alt inactiveTime < 5 minutos
            T->>T: Usuario activo, continuar
        else inactiveTime >= 5 minutos (300,000ms)
            T->>T: console.log("⏰ usuario123 inactivo por 5+ min")
            
            T->>S: Obtener socket<br/>const socket = io.sockets.sockets.get(socketId)
            
            alt Socket existe
                T->>S: socket.emit('inactivityDisconnect', {<br/>  message: 'Desconectado por inactividad'<br/>})
                
                S-->>F: Event 'inactivityDisconnect'
                F->>F: setIsKicked(true)
                F->>F: setDisconnectReason('inactividad')
                F->>F: Mostrar overlay<br/>"⏰ Desconectado por inactividad prolongada"
                F->>F: socket.disconnect()
                F->>F: setTimeout(() => navigate('/'), 3000)
                F-->>U: Desconectado, redirigiendo...
                
                T->>S: socket.leave(roomId)
                
                T->>S: delete userSessions[nickname]
                Note right of T: Limpiar sesión
                
                T->>S: io.to(roomId).emit('userLeft', {<br/>  nickname,<br/>  reason: 'inactivity'<br/>})
                Note right of T: Notificar a sala
            end
        end
    end
    
    Note over T: Monitoreo continuo:<br/>console.log cada 60s<br/>"📊 Sesiones activas: X"
```

**Configuración:**
- **Timeout**: 5 minutos sin actividad
- **Check Interval**: Cada 30 segundos
- **Heartbeat Client**: Cada 2 minutos
- **Actividad detectada en**:
  - Envío de mensaje
  - Escribir en input
  - Heartbeat automático
  - Entrar a sala

**Tiempo desde inactividad hasta desconexión:** ~5 minutos

**Logs del servidor:**
```
⏰ usuario123 inactivo por 305 segundos - Desconectando...
📊 Sesiones activas: 12
  👤 usuario456 - Inactivo: 45s - Sala: 507f...
  👤 usuario789 - Inactivo: 120s - Sala: 507f...
```

---

## Resumen de Tiempos

| Operación | Tiempo Estimado | Tipo |
|-----------|----------------|------|
| Registro | 200-500ms | HTTP |
| Login | 150-400ms | HTTP |
| Crear Sala | 200-600ms | HTTP + WS |
| Entrar a Sala | 300-800ms | WebSocket |
| Enviar Mensaje | 50-200ms | WebSocket |
| Editar Mensaje | 100-300ms | WebSocket |
| Eliminar Mensaje | 150-400ms | WebSocket |
| Subir Archivo | 500ms-5s | HTTP |
| Expulsar Usuario | 100-300ms | WebSocket |
| Reemplazar Sesión | 200-500ms | WebSocket |
| Desconexión Inactividad | ~5 minutos | Background |

---

## Eventos Socket.IO

### Cliente → Servidor

| Evento | Payload | Descripción |
|--------|---------|-------------|
| `joinRoom` | `{ nickname, roomId }` | Entrar a sala |
| `sendMessage` | `{ roomId, nickname, content, fileUrl? }` | Enviar mensaje |
| `editMessage` | `{ messageId, newContent }` | Editar mensaje |
| `deleteMessage` | `{ messageId, nickname }` | Eliminar mensaje |
| `kickUser` | `{ nickname, roomId, adminId }` | Expulsar usuario (admin) |
| `userActivity` | `{}` | Heartbeat (mantener activo) |
| `disconnect` | `{}` | Desconexión (automático) |

### Servidor → Cliente

| Evento | Payload | Descripción |
|--------|---------|-------------|
| `loadMessages` | `[{ _id, content, sender, ... }]` | Cargar historial |
| `newMessage` | `{ _id, content, sender, ... }` | Nuevo mensaje (broadcast) |
| `messageEdited` | `{ messageId, newContent, isEdited }` | Mensaje editado (broadcast) |
| `messageDeleted` | `{ messageId }` | Mensaje eliminado (broadcast) |
| `userJoined` | `{ nickname, users: [...] }` | Usuario entró (broadcast) |
| `userLeft` | `{ nickname, reason? }` | Usuario salió (broadcast) |
| `kicked` | `{ reason }` | Expulsado por admin |
| `sessionReplaced` | `{ message }` | Sesión reemplazada |
| `inactivityDisconnect` | `{ message }` | Desconectado por inactividad |
| `systemMessage` | `{ content }` | Mensaje del sistema |
| `error` | `{ message }` | Error general |

---

**Última actualización:** Noviembre 2025

**Nota:** Estos diagramas están diseñados para ser renderizados con Mermaid. Puedes visualizarlos en:
- GitHub (renderizado automático)
- VS Code con extensión "Markdown Preview Mermaid Support"
- [Mermaid Live Editor](https://mermaid.live/)
