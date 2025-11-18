# 🚀 Guía para Subir el Proyecto a GitHub

## 📋 Preparación

### 1. Verificar archivos ignorados
Los siguientes archivos/carpetas **NO** se subirán a GitHub (ya están en `.gitignore`):
- ✅ `node_modules/` - Dependencias (se instalan con npm install)
- ✅ `.env` - Variables de entorno sensibles
- ✅ `uploads/*` - Archivos subidos por usuarios
- ✅ `coverage/` - Reportes de cobertura de tests
- ✅ `logs/` - Archivos de log
- ✅ `.vscode/`, `.idea/` - Configuraciones de IDE

### 2. Archivos incluidos
Los siguientes archivos **SÍ** se subirán:
- ✅ `.env.example` - Plantilla de variables de entorno
- ✅ `uploads/.gitkeep` - Para mantener la carpeta en el repo
- ✅ Código fuente completo
- ✅ Documentación (README.md, TESTING.md, etc.)
- ✅ Archivos de configuración (package.json, jest.config.js, etc.)

---

## 🔧 Pasos para Subir a GitHub

### Opción 1: Desde la Terminal (Recomendado)

```bash
# 1. Inicializar el repositorio Git (si no está inicializado)
cd "d:\8vo\APLICACIONES DISTRIBUIDAS\1parcial\chatapp"
git init

# 2. Configurar tu usuario de Git (si es primera vez)
git config user.name "Tu Nombre"
git config user.email "tu.email@ejemplo.com"

# 3. Agregar todos los archivos (respetando .gitignore)
git add .

# 4. Verificar qué archivos se van a subir
git status

# 5. Hacer el primer commit
git commit -m "Initial commit: Sistema de chat en tiempo real con salas y autenticación"

# 6. Crear el repositorio en GitHub (ve a github.com y crea un nuevo repo)
# No inicialices el repo con README, .gitignore o licencia (ya los tenemos)

# 7. Conectar con GitHub (reemplaza 'usuario' y 'nombre-repo' con tus datos)
git remote add origin https://github.com/usuario/nombre-repo.git

# 8. Subir el código
git branch -M main
git push -u origin main
```

### Opción 2: Desde VS Code

1. **Inicializar repositorio**:
   - Abre la carpeta del proyecto en VS Code
   - Click en el ícono de "Source Control" (panel izquierdo)
   - Click en "Initialize Repository"

2. **Hacer commit**:
   - Escribe un mensaje: "Initial commit: Sistema de chat en tiempo real"
   - Click en el botón ✓ (checkmark) para hacer commit

3. **Publicar a GitHub**:
   - Click en "Publish to GitHub"
   - Selecciona si quieres repo público o privado
   - Selecciona los archivos a incluir (VS Code respeta .gitignore)
   - Click en "Publish"

---

## 📝 Commits Subsecuentes

Cuando hagas cambios futuros:

```bash
# 1. Ver qué cambió
git status

# 2. Agregar archivos modificados
git add .

# 3. Hacer commit con mensaje descriptivo
git commit -m "Descripción de los cambios"

# 4. Subir cambios
git push
```

---

## ⚠️ Importante: Antes de Subir

### Verificar que NO se suba información sensible:

```bash
# Ver qué archivos se van a subir
git status

# Ver contenido que se subirá
git diff --cached
```

### Revisar que .env NO esté en el commit:
```bash
# Este comando NO debe mostrar .env
git ls-files | grep .env
```

Si por error agregaste .env, quítalo:
```bash
git rm --cached backend/.env
git rm --cached frontend/.env
git commit -m "Remove .env files"
```

---

## 🔒 Seguridad

### Variables de Entorno
Los archivos `.env` contienen información sensible y **NO** se suben a GitHub.

Los colaboradores deben:
1. Copiar `.env.example` a `.env`
2. Llenar con sus propios valores

```bash
# Backend
cd backend
cp .env.example .env
# Editar .env con valores reales

# Frontend
cd frontend
cp .env.example .env
# Editar .env con valores reales
```

---

## 📦 Clonar el Proyecto (para otros desarrolladores)

```bash
# 1. Clonar el repositorio
git clone https://github.com/usuario/nombre-repo.git
cd nombre-repo

# 2. Instalar dependencias del backend
cd backend
npm install
cp .env.example .env
# Editar .env con configuración local

# 3. Instalar dependencias del frontend
cd ../frontend
npm install
cp .env.example .env
# Editar .env con configuración local

# 4. Ejecutar MongoDB
# Asegúrate de tener MongoDB corriendo

# 5. Iniciar el backend
cd ../backend
npm run dev

# 6. Iniciar el frontend (en otra terminal)
cd ../frontend
npm run dev
```

---

## 📚 Estructura del README en GitHub

Tu README.md principal ya está completo con:
- ✅ Descripción del proyecto
- ✅ Características principales
- ✅ Tecnologías utilizadas
- ✅ Instrucciones de instalación
- ✅ Guía de uso
- ✅ Documentación de tests
- ✅ Arquitectura del sistema

---

## 🎯 Checklist Final Antes de Subir

- [ ] `.gitignore` creado en raíz y backend
- [ ] `.env.example` creado en backend y frontend
- [ ] `.env` NO está en el repositorio
- [ ] `node_modules/` NO está en el repositorio
- [ ] `uploads/.gitkeep` existe pero `uploads/*` archivos no se suben
- [ ] README.md está actualizado
- [ ] Todos los tests pasan (`npm test`)
- [ ] El código compila sin errores

---

## 💡 Tips Adicionales

### Crear ramas para features
```bash
# Crear rama para nueva feature
git checkout -b feature/nombre-feature

# Trabajar en la rama
git add .
git commit -m "Añadir feature"

# Subir rama
git push -u origin feature/nombre-feature

# Hacer Pull Request en GitHub
# Después de aprobar, hacer merge a main
```

### .gitignore global para tu sistema
```bash
# Crear .gitignore global para tu computadora
git config --global core.excludesfile ~/.gitignore_global

# Agregar archivos específicos de tu sistema
echo ".DS_Store" >> ~/.gitignore_global
echo "Thumbs.db" >> ~/.gitignore_global
```

---

## 🆘 Problemas Comunes

### "Repository not found"
- Verifica que creaste el repo en GitHub
- Verifica la URL del remote: `git remote -v`

### "Permission denied"
- Configura SSH keys o usa HTTPS con token
- Genera token en: GitHub → Settings → Developer settings → Personal access tokens

### Archivos sensibles ya en el repo
```bash
# Eliminar archivo del historial
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch backend/.env" \
  --prune-empty --tag-name-filter cat -- --all

# Forzar push (¡cuidado!)
git push origin --force --all
```

---

**¡Listo!** Tu proyecto está preparado para GitHub. 🎉
