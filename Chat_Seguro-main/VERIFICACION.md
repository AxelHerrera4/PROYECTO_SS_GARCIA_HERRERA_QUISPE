# ✅ Lista de Verificación - Inicio con Docker

Usa esta lista para asegurarte de que todo funciona correctamente después de iniciar con Docker.

---

## 🔍 Paso 1: Verificar que Docker está corriendo

```bash
docker --version
docker ps
```

**Resultado esperado:**
- Muestra la versión de Docker
- Lista los contenedores corriendo

---

## 🔍 Paso 2: Verificar contenedores activos

```bash
docker-compose ps
```

**Resultado esperado:**
```
NAME                  STATUS
chatapp-mongodb       Up (healthy)
chatapp-backend       Up
chatapp-frontend      Up
```

✅ Los 3 contenedores deben estar en estado **Up**

---

## 🔍 Paso 3: Verificar logs del backend

```bash
docker-compose logs backend | grep -i "admin"
```

**Resultado esperado:**
```
✅ Admin predeterminado creado: admin/admin
   O
ℹ️ Admin predeterminado ya existe
```

✅ El admin debe haberse creado automáticamente

---

## 🔍 Paso 4: Verificar conexión a MongoDB

```bash
docker-compose logs backend | grep -i "mongodb"
```

**Resultado esperado:**
```
✅ Conectado a MongoDB
```

---

## 🔍 Paso 5: Acceder al frontend

Abre tu navegador y ve a: **http://localhost:5173**

**Resultado esperado:**
- ✅ Se carga la página de login/registro
- ✅ No aparecen errores en la consola del navegador (F12)

---

## 🔍 Paso 6: Probar login de admin

1. En http://localhost:5173, busca el botón **"Panel Admin"**
2. Ingresa:
   - **Usuario**: `admin`
   - **Contraseña**: `admin`
3. Haz clic en **"Iniciar Sesión"**

**Resultado esperado:**
- ✅ Te redirige al panel de administración
- ✅ Puedes ver la lista de salas (puede estar vacía)

---

## 🔍 Paso 7: Crear una sala de prueba

En el panel de admin:

1. Haz clic en **"Crear Sala"**
2. Ingresa:
   - **Nombre**: `Sala de Prueba`
   - **Tipo**: `Multimedia`
   - **PIN**: `1234` (o deja que se genere automático)
3. Haz clic en **"Crear"**

**Resultado esperado:**
- ✅ La sala aparece en la lista
- ✅ Se muestra un mensaje de éxito

---

## 🔍 Paso 8: Unirse a la sala como usuario

1. Abre una **nueva ventana de incógnito** (Ctrl+Shift+N)
2. Ve a http://localhost:5173
3. Haz clic en **"Unirse a Sala"**
4. Ingresa:
   - **Nickname**: `TestUser`
   - **PIN de Sala**: `1234` (el que creaste)
5. Haz clic en **"Unirse"**

**Resultado esperado:**
- ✅ Te redirige a la sala de chat
- ✅ Ves el nombre de la sala arriba
- ✅ Puedes escribir mensajes

---

## 🔍 Paso 9: Enviar un mensaje

En la sala de chat:

1. Escribe: `Hola, esto es una prueba`
2. Presiona **Enter** o haz clic en **Enviar**

**Resultado esperado:**
- ✅ El mensaje aparece en el chat
- ✅ Se guarda en MongoDB (persiste al recargar)

---

## 🔍 Paso 10: Subir un archivo (solo salas multimedia)

1. Haz clic en el ícono de **📎 clip**
2. Selecciona una imagen (JPG, PNG, GIF)
3. Haz clic en **Enviar**

**Resultado esperado:**
- ✅ La imagen aparece en el chat
- ✅ Se puede abrir en una nueva pestaña

---

## 🔍 Paso 11: Verificar encriptación

```bash
# Conectarse a MongoDB
docker exec -it chatapp-mongodb mongosh chatapp

# Dentro de mongosh, ejecutar:
db.messages.findOne()
```

**Resultado esperado:**
```javascript
{
  _id: ObjectId("..."),
  sender: "iv:encryptedData...",    // ✅ ENCRIPTADO
  content: "iv:encryptedData...",   // ✅ ENCRIPTADO
  room: ObjectId("..."),
  type: "text",
  timestamp: ISODate("...")
}
```

✅ Los campos `sender` y `content` deben estar encriptados (formato `iv:...`)

Para salir de mongosh:
```
exit
```

---

## 🔍 Paso 12: Verificar usuarios activos

Con la sala abierta en ambas ventanas:

**Resultado esperado:**
- ✅ En la lista de usuarios activos ves: `TestUser`
- ✅ Si cierras una ventana, el usuario desaparece de la lista

---

## 🔍 Paso 13: Probar expulsión (admin)

En la ventana del **admin**:

1. Abre la misma sala (PIN: 1234)
2. Busca el usuario `TestUser` en la lista
3. Haz clic en **"Expulsar"**

**Resultado esperado:**
- ✅ `TestUser` es desconectado inmediatamente
- ✅ En la ventana de incógnito aparece: "Has sido expulsado"
- ✅ No puede volver a entrar con el mismo PIN

---

## 🔍 Paso 14: Detener y reiniciar

```bash
docker-compose down
docker-compose up -d
```

Espera 30 segundos y luego:

1. Abre http://localhost:5173
2. Login como admin (admin/admin)

**Resultado esperado:**
- ✅ La sala "Sala de Prueba" sigue existiendo
- ✅ Los mensajes anteriores están guardados
- ✅ El admin sigue funcionando

---

## 🎉 ¡TODO FUNCIONA!

Si pasaste todos los pasos, tu instalación está **100% funcional**.

---

## ❌ Si algo falló

### Problema: Contenedores no inician

```bash
docker-compose down -v
docker-compose up --build
```

### Problema: Admin no existe

```bash
docker-compose restart backend
docker-compose logs backend | grep -i admin
```

### Problema: Frontend no carga

1. Verifica que el puerto 5173 no esté ocupado
2. Revisa logs: `docker-compose logs frontend`

### Problema: Backend no conecta a MongoDB

```bash
docker-compose logs backend | grep -i error
docker-compose restart mongodb
docker-compose restart backend
```

---

## 📞 Soporte

Si ningún paso funciona:

1. Copia todos los logs: `docker-compose logs > logs.txt`
2. Revisa `INSTRUCCIONES_DOCKER.md`
3. Verifica que Docker Desktop esté corriendo

---

**Última actualización:** 14 de Noviembre, 2025
