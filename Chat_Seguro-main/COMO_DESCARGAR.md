# 📥 Cómo Descargar y Usar Este Proyecto

## 🚀 Inicio Rápido - 3 Pasos

### 1️⃣ Clonar el repositorio

Abre tu terminal (CMD, PowerShell, Git Bash, o Terminal de Linux/Mac) y ejecuta:

```bash
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp
```

**¿No tienes Git?** Descárgalo desde: https://git-scm.com/downloads

---

### 2️⃣ Instalar Docker Desktop

Si aún no tienes Docker instalado:

**Windows / Mac:**
- Descarga Docker Desktop: https://www.docker.com/products/docker-desktop
- Instálalo y ábrelo
- Espera a que diga "Docker is running"

**Linux:**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo systemctl start docker
```

---

### 3️⃣ Iniciar la aplicación

Una vez que tengas el proyecto clonado y Docker corriendo:

**Windows:**
```cmd
Doble clic en INICIAR.bat
```

O desde PowerShell/CMD:
```cmd
.\INICIAR.bat
```

**Linux / Mac:**
```bash
chmod +x INICIAR.sh
./INICIAR.sh
```

**⏳ Espera 2-3 minutos** la primera vez mientras Docker descarga y construye todo.

---

## ✅ Verificar que funciona

1. El navegador debería abrirse automáticamente en: **http://localhost:5173**

2. Si no se abre automáticamente, ábrelo manualmente:
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:5000

3. **Credenciales de admin:**
   - Usuario: `admin`
   - Contraseña: `admin`

---

## 📋 Requisitos

- **Git** (para clonar el repositorio)
- **Docker Desktop** (Windows/Mac) o **Docker Engine** (Linux)
- **Conexión a Internet** (para descargar dependencias la primera vez)

---

## 🎯 Estructura del Proyecto Descargado

```
chatapp/
├── INICIAR.bat              ← Ejecuta esto en Windows
├── INICIAR.sh               ← Ejecuta esto en Linux/Mac
├── LEEME_PRIMERO.md        ← Guía completa
├── INSTRUCCIONES_DOCKER.md ← Guía detallada de Docker
├── VERIFICACION.md         ← Pasos de verificación
├── docker-compose.yml      ← Configuración de Docker
├── backend/                ← Código del servidor
└── frontend/               ← Código de la interfaz
```

---

## 🛠️ Comandos Útiles

```bash
# Ver logs en tiempo real
docker-compose logs -f

# Detener la aplicación
docker-compose down

# Reiniciar
docker-compose restart

# Ver estado de contenedores
docker-compose ps

# Reconstruir desde cero
docker-compose down -v
docker-compose up --build
```

---

## 💡 Opciones de Descarga

### Opción 1: Con Git (Recomendado)
```bash
git clone https://github.com/cjgranda19/chatapp.git
cd chatapp
```

### Opción 2: Descargar ZIP
1. Ve a: https://github.com/cjgranda19/chatapp
2. Haz clic en el botón verde **"Code"**
3. Selecciona **"Download ZIP"**
4. Extrae el archivo ZIP
5. Abre la carpeta extraída en tu terminal
6. Ejecuta `INICIAR.bat` o `INICIAR.sh`

---

## ❓ Problemas Comunes

### "git no se reconoce como comando"
- Instala Git desde: https://git-scm.com/downloads
- Reinicia tu terminal después de instalarlo

### "Docker no está corriendo"
- Abre Docker Desktop
- Espera a que diga "Docker is running"
- Vuelve a ejecutar el script de inicio

### "Puerto ya en uso"
- Cierra otras aplicaciones que usen los puertos 5000 o 5173
- O edita `docker-compose.yml` para cambiar los puertos

---

## 📚 Más Información

- **LEEME_PRIMERO.md** - Guía simple y completa
- **INSTRUCCIONES_DOCKER.md** - Guía detallada de Docker
- **VERIFICACION.md** - Cómo verificar que todo funciona
- **CONFIGURACION_FINAL.md** - Detalles técnicos

---

## 🎉 ¡Eso es todo!

Con estos 3 pasos ya puedes usar la aplicación:

1. ✅ Clonar el repositorio
2. ✅ Tener Docker corriendo
3. ✅ Ejecutar `INICIAR.bat` o `INICIAR.sh`

**No necesitas:**
- ❌ Instalar Node.js
- ❌ Instalar MongoDB
- ❌ Configurar variables de entorno
- ❌ Crear archivos .env

**¡Docker lo hace TODO automáticamente!**

---

**Repositorio:** https://github.com/cjgranda19/chatapp  
**Última actualización:** 14 de Noviembre, 2025
