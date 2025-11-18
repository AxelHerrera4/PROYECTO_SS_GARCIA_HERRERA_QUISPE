# 🧪 Guía de Prueba: Sesión Única y Desconexión por Inactividad

## 📋 Funcionalidades Implementadas

### 1. ✅ Sesión Única por Dispositivo
**Requisito:** Solo se permite una conexión activa por usuario (nickname)

### 2. ✅ Desconexión por Inactividad
**Requisito:** Usuarios inactivos por más de 5 minutos son desconectados automáticamente

---

## 🔬 Cómo Probar

### Prueba 1: Sesión Única por Dispositivo

1. **Abre el frontend** en el navegador (http://localhost:5173 o 5174)
2. **Inicia sesión** con un usuario (ej: "usuario1")
3. **Únete a una sala** con un PIN
4. **Abre otra pestaña o navegador** (simulando otro dispositivo)
5. **Inicia sesión con el mismo usuario** ("usuario1")
6. **Únete a cualquier sala**

**✅ Resultado Esperado:**
- La **primera pestaña** mostrará un overlay: "🔄 Sesión reemplazada - Tu sesión ha sido reemplazada por otro dispositivo"
- La **primera pestaña** será redirigida al dashboard en 3 segundos
- La **segunda pestaña** funcionará normalmente
- En la sala antigua, aparecerá un mensaje: "usuario1 se desconectó (sesión desde otro dispositivo)"

**🖥️ Logs del Backend:**
```
🔄 usuario1 reemplazó su sesión anterior (dispositivo diferente)
✅ Sesión registrada para usuario1 - Socket: xyz123 - Sala: abc789
```

---

### Prueba 2: Desconexión por Inactividad

1. **Inicia sesión** y únete a una sala
2. **NO hagas nada** durante 5 minutos
   - No escribas mensajes
   - No muevas el mouse en el input
   - No hagas click en nada

**⚠️ Para prueba rápida:** Modifica temporalmente `INACTIVITY_TIMEOUT` en `server.js`:
```js
const INACTIVITY_TIMEOUT = 30 * 1000; // 30 segundos (solo para testing)
```

**✅ Resultado Esperado:**
- Después de 5 minutos (o 30 segundos si lo modificaste), aparecerá un overlay: "⏰ Desconectado por inactividad"
- Serás redirigido al dashboard en 3 segundos
- En la sala, aparecerá: "usuario1 fue desconectado por inactividad"

**🖥️ Logs del Backend:**
```
⏰ usuario1 desconectado por inactividad (305s)
```

---

### Prueba 3: Mantener Sesión Activa

**Acciones que mantienen la sesión activa:**
- ✅ Escribir en el input de mensaje (cada tecla)
- ✅ Enviar un mensaje
- ✅ Automáticamente cada 2 minutos (heartbeat)

**Cómo probar:**
1. Únete a una sala
2. Cada 2-3 minutos, escribe algo (aunque no lo envíes)
3. Deja la pestaña abierta por 10+ minutos

**✅ Resultado Esperado:**
- NO serás desconectado
- La sesión se mantendrá activa

---

## 📊 Monitoreo del Backend

El backend registra información cada minuto en consola:

```
📊 Sesiones activas: 2
   👤 usuario1 - Inactivo: 45s - Sala: 674859abc123
   👤 usuario2 - Inactivo: 120s - Sala: 674859abc456
```

---

## 🔧 Configuración

### Archivo: `backend/src/server.js`

```javascript
// Tiempo de inactividad permitido
const INACTIVITY_TIMEOUT = 5 * 60 * 1000; // 5 minutos

// Frecuencia de verificación
const CHECK_INTERVAL = 30 * 1000; // 30 segundos
```

### Archivo: `frontend/src/components/ChatRoom.jsx`

```javascript
// Frecuencia de heartbeat (ping de actividad)
const activityInterval = setInterval(() => {
  socket.emit("userActivity", { nickname });
}, 2 * 60 * 1000); // 2 minutos
```

---

## ✅ Checklist de Validación

- [ ] Un usuario con el mismo nickname reemplaza la sesión anterior
- [ ] La sesión anterior recibe notificación y es desconectada
- [ ] Aparece mensaje en la sala cuando alguien es desconectado
- [ ] Usuarios inactivos por 5+ minutos son desconectados
- [ ] Escribir en el input mantiene la sesión activa
- [ ] El heartbeat automático funciona cada 2 minutos
- [ ] Los overlays muestran el mensaje correcto según el motivo
- [ ] La redirección al dashboard funciona correctamente
- [ ] Los logs del backend son claros y descriptivos

---

## 🐛 Debugging

Si algo no funciona:

1. **Revisa la consola del navegador** (F12) - Busca logs con emoji 🔄, ⏰, 🚫
2. **Revisa la terminal del backend** - Busca logs con los mismos emojis
3. **Verifica que Socket.IO esté conectado** - En consola: `socket.connected` debe ser `true`
4. **Comprueba las variables de entorno** - `CLIENT_ORIGIN` debe coincidir con la URL del frontend

---

## 📝 Notas Técnicas

### Estructura de `userSessions`:
```javascript
{
  "usuario1": {
    socketId: "abc123",
    roomId: "674859abc123", 
    lastActivity: 1699483200000
  }
}
```

### Eventos Socket.IO:
- `sessionReplaced` - Sesión reemplazada por otro dispositivo
- `inactivityDisconnect` - Desconexión por inactividad
- `userActivity` - Ping de actividad del cliente
- `kicked` - Usuario expulsado por admin

---

## 🎯 Cumplimiento de Requisitos

✅ **"Los usuarios solo podrán unirse a una sala de chat a la vez desde un solo dispositivo"**
- Implementado mediante control de sesiones único por nickname
- Socket ID único por sesión
- Desconexión automática de sesión anterior

✅ **"Desconexión automática al cerrar el navegador o inactividad prolongada"**
- Timeout de 5 minutos
- Verificación cada 30 segundos
- Heartbeat automático cada 2 minutos
- Actualización de actividad al escribir/enviar mensajes
