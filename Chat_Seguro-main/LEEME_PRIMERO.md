# 🎯 PARA TUS COMPAÑEROS DE TRABAJO

## ¿Qué hace esta aplicación?

Sistema de **chat en tiempo real** con:
- ✅ Salas públicas y privadas con PIN
- ✅ Mensajes encriptados
- ✅ Envío de archivos e imágenes
- ✅ Panel de administración
- ✅ Usuarios activos en tiempo real

---

## 🚀 Cómo usar (3 pasos)

### 1. Descargar el proyecto desde GitHub

**Opción A - Con Git (Recomendado):**
```bash
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp
```

**Opción B - Sin Git (Descargar ZIP):**
1. Ve a: https://github.com/cjgranda19/chatapp
2. Clic en el botón verde **"Code"**
3. Selecciona **"Download ZIP"**
4. Extrae el archivo y abre la carpeta

**¿No tienes Git?** Descárgalo desde: https://git-scm.com/downloads

---

### 2. Instalar Docker Desktop

Si no lo tienes:
- **Windows/Mac**: https://www.docker.com/products/docker-desktop
- **Linux**: `sudo apt install docker.io docker-compose`

Asegúrate de que Docker esté corriendo (debe decir "Docker is running")

---

### 3. Iniciar la aplicación

**Windows:**
```
Doble clic en INICIAR.bat
```

**Linux/Mac:**
```bash
chmod +x INICIAR.sh
./INICIAR.sh
```

**⏳ Espera 2-3 minutos la primera vez**

---

## ✅ Verificar que funciona

### El navegador se abre automáticamente en:
http://localhost:5173

### Credenciales de admin:
- **Usuario**: `admin`
- **Contraseña**: `admin`

---

## 📱 Cómo usar la app

### Como Admin:

1. Haz clic en **"Panel Admin"**
2. Login con `admin` / `admin`
3. Crea una sala:
   - Nombre: `Mi Sala`
   - Tipo: `Multimedia` (permite imágenes/archivos)
   - PIN: `1234` (o automático)
4. Copia el PIN de la sala

### Como Usuario:

1. Haz clic en **"Unirse a Sala"**
2. Ingresa:
   - Tu nickname: `Juan`
   - PIN de la sala: `1234`
3. ¡Listo! Ya puedes chatear

---

## 🛑 Cómo detener la aplicación

```bash
docker-compose down
```

---

## 🔄 Cómo reiniciar

```bash
docker-compose restart
```

---

## 📊 Ver logs (si algo no funciona)

```bash
docker-compose logs -f
```

Presiona `Ctrl+C` para salir

---

## ❓ Problemas Comunes

### "Docker no está corriendo"

1. Abre Docker Desktop
2. Espera a que diga "Docker is running"
3. Vuelve a ejecutar `INICIAR.bat` o `INICIAR.sh`

### "Puerto ya en uso"

Alguien más está usando el puerto 5173 o 5000. Opciones:

**Opción A - Detener lo que esté usando el puerto:**
```bash
# Windows
netstat -ano | findstr :5173
taskkill /PID <número_del_pid> /F

# Linux/Mac
lsof -i :5173
kill -9 <PID>
```

**Opción B - Cambiar el puerto:**

Edita `docker-compose.yml` y cambia:
```yaml
ports:
  - "3000:5173"  # En lugar de "5173:5173"
```

Luego accede en http://localhost:3000

### "Admin no aparece"

```bash
# Ver si se creó
docker-compose logs backend | grep -i admin

# Debería decir:
# ✅ Admin predeterminado creado: admin/admin

# Si no aparece, reinicia el backend:
docker-compose restart backend
```

### "No puedo subir archivos"

Asegúrate de crear una sala de tipo **Multimedia**.  
Las salas de tipo **Texto** no permiten archivos.

---

## 🎯 Accesos Rápidos

- **Aplicación**: http://localhost:5173
- **API Backend**: http://localhost:5000
- **MongoDB**: `localhost:27017`

---

## 🗑️ Eliminar TODO (incluyendo datos)

⚠️ **CUIDADO**: Esto borra TODOS los mensajes y salas

```bash
docker-compose down -v
```

---

## 📚 Más Información

- `INSTRUCCIONES_DOCKER.md` - Guía completa con más detalles
- `VERIFICACION.md` - 14 pasos para verificar que todo funciona
- `README.md` - Documentación técnica completa

---

## 🎉 ¡Listo!

Con estos 3 pasos tu equipo puede usar la aplicación sin problemas:

1. ✅ Instalar Docker
2. ✅ Clonar el proyecto
3. ✅ Ejecutar `INICIAR.bat` o `INICIAR.sh`

**¡Sin configuraciones, sin instalar Node.js, sin MongoDB!**

Docker lo hace TODO automáticamente.

---

**¿Necesitas ayuda?**
- Revisa los logs: `docker-compose logs -f`
- Lee `INSTRUCCIONES_DOCKER.md` para más detalles
- Verifica que Docker Desktop esté corriendo

---

**Última actualización:** 14 de Noviembre, 2025  
**Versión:** 2.0 - Docker Ready ✅
