# 🛡️ Seguridad Implementada

Este documento describe todas las medidas de seguridad implementadas en la aplicación de chat.

## 📋 Tabla de Contenidos
1. [Protección contra Inyecciones](#protección-contra-inyecciones)
2. [Validación de Entrada](#validación-de-entrada)
3. [Headers de Seguridad](#headers-de-seguridad)
4. [Autenticación y Autorización](#autenticación-y-autorización)
5. [Limitaciones de Recursos](#limitaciones-de-recursos)

---

## 🚫 Protección contra Inyecciones

### NoSQL Injection
**Middleware:** `express-mongo-sanitize`
- Elimina caracteres especiales de MongoDB (`$`, `.`) de los datos de entrada
- Reemplaza caracteres prohibidos con `_`
- Registra intentos de inyección en los logs

**Ejemplo de protección:**
```javascript
// Entrada maliciosa
{ "username": { "$ne": null } }

// Después de sanitización
{ "username": "{ _ne : null }" }
```

### XSS (Cross-Site Scripting)
**Librería:** `validator.escape()`
- Escapa caracteres HTML especiales
- Previene ejecución de scripts maliciosos
- Aplicado en todos los campos de texto

**Ejemplo de protección:**
```javascript
// Entrada maliciosa
"<script>alert('XSS')</script>"

// Después de sanitización
"&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;&#x2F;script&gt;"
```

---

## ✅ Validación de Entrada

### Validaciones Implementadas

#### 1. **Creación de Salas**
```javascript
validateCreateRoom:
- name: 3-50 caracteres, solo letras, números, espacios, guiones
- type: debe ser "texto" o "multimedia"
- pin: opcional, exactamente 4 dígitos numéricos
```

#### 2. **Login de Usuario**
```javascript
validateUserLogin:
- nickname: 2-20 caracteres, solo letras, números, guiones y guiones bajos
```

#### 3. **Login de Admin**
```javascript
validateAdminLogin:
- username: 3-20 caracteres, solo letras, números y guiones bajos
- password: 3-50 caracteres
```

#### 4. **Unirse a Sala**
```javascript
validateJoinRoom:
- nickname: 2-20 caracteres
- pin: exactamente 4 dígitos numéricos
```

#### 5. **Mensajes**
```javascript
validateMessage:
- roomId: debe ser un ID válido de MongoDB
- sender: 2-20 caracteres
- content: máximo 5000 caracteres
- type: debe ser text, file, image, video o audio
```

#### 6. **IDs de MongoDB**
```javascript
validateMongoId:
- Verifica que el ID tenga formato válido de ObjectId
```

### Expresiones Regulares Usadas
```javascript
// Nombres de sala
/^[a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ\-_]+$/

// Nicknames
/^[a-zA-Z0-9_\-]+$/

// Username admin
/^[a-zA-Z0-9_]+$/

// PIN
/^[0-9]+$/
```

---

## 🔒 Headers de Seguridad

### Helmet
Configura headers HTTP seguros automáticamente:

```javascript
helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false // Para desarrollo
})
```

**Headers configurados:**
- `X-Content-Type-Options: nosniff` - Previene MIME sniffing
- `X-Frame-Options: SAMEORIGIN` - Protege contra clickjacking
- `X-XSS-Protection: 1; mode=block` - Protección XSS básica
- `Strict-Transport-Security` - Fuerza HTTPS (producción)

---

## 🔐 Autenticación y Autorización

### JWT (JSON Web Tokens)
- **Expiración:** 7 días
- **Secret:** Variable de entorno `JWT_SECRET`
- **Almacenamiento:** LocalStorage en cliente

### Middlewares de Autenticación

#### 1. `protect` - Solo Usuarios
```javascript
Busca en modelo User
Verifica token JWT
Adjunta req.user
```

#### 2. `protectAdmin` - Solo Admins
```javascript
Busca en modelo Admin
Verifica token JWT
Adjunta req.user
```

#### 3. `protectAny` - Usuarios o Admins
```javascript
Busca primero en User, luego en Admin
Verifica token JWT
Adjunta req.user
```

### Rutas Protegidas
```
GET    /api/admin/rooms          [protectAdmin]
PUT    /api/admin/rooms/:id      [protectAdmin]
DELETE /api/admin/rooms/:id      [protectAdmin]
POST   /api/rooms                [protectAny]
```

---

## ⚖️ Limitaciones de Recursos

### Tamaño de Payload
```javascript
express.json({ limit: '10mb' })
express.urlencoded({ limit: '10mb' })
```
**Previene:** Ataques de denegación de servicio (DoS)

### Longitud de Campos
- **Nickname:** Máximo 20 caracteres
- **Nombre de sala:** Máximo 50 caracteres
- **Contenido de mensaje:** Máximo 5000 caracteres
- **PIN:** Exactamente 4 caracteres

---

## 🔍 Logs de Seguridad

### Eventos Registrados
```javascript
⚠️ Intento de inyección detectado en ${key}
❌ Token inválido o expirado
❌ Usuario no encontrado
❌ Admin no encontrado
```

---

## 📦 Dependencias de Seguridad

```json
{
  "express-validator": "^7.0.0",  // Validación de entrada
  "validator": "^13.11.0",         // Sanitización de strings
  "express-mongo-sanitize": "^2.2.0", // Protección NoSQL
  "helmet": "^7.1.0",              // Headers de seguridad
  "bcryptjs": "^2.4.3",            // Hash de contraseñas
  "jsonwebtoken": "^9.0.2"         // Autenticación JWT
}
```

---

## ✅ Checklist de Seguridad

- [x] Validación de todos los inputs
- [x] Sanitización contra XSS
- [x] Protección contra inyección NoSQL
- [x] Headers de seguridad (Helmet)
- [x] Autenticación JWT
- [x] Hash de contraseñas con bcrypt
- [x] CORS configurado
- [x] Limitación de tamaño de payload
- [x] Validación de IDs de MongoDB
- [x] Expresiones regulares para patrones
- [x] Logs de intentos de inyección
- [x] Middlewares de autorización

---

## 🚀 Recomendaciones para Producción

1. **HTTPS:** Habilitar SSL/TLS
2. **Rate Limiting:** Limitar solicitudes por IP
   ```bash
   npm install express-rate-limit
   ```
3. **Content Security Policy:** Habilitar CSP en Helmet
4. **Variables de Entorno:** Usar secretos fuertes
5. **Monitoreo:** Implementar logs centralizados
6. **Actualizaciones:** Mantener dependencias actualizadas
   ```bash
   npm audit
   npm audit fix
   ```

---

## 📚 Referencias

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
