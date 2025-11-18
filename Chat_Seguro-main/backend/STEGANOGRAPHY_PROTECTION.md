# 🔒 Protección contra Esteganografía

## ¿Qué es la Esteganografía?

La esteganografía es la técnica de **ocultar archivos dentro de otros archivos**. Por ejemplo:
- Ocultar un archivo ZIP dentro de una imagen JPG
- Agregar un ejecutable (.exe) al final de un archivo PDF
- Esconder malware dentro de archivos de audio
- Ocultar documentos sensibles en imágenes

## 🛡️ Sistema de Detección Implementado

### Niveles de Protección

#### 1️⃣ **Validación Rápida** (Pre-filtro)
- ✅ Bloquea extensiones peligrosas: `.exe`, `.bat`, `.cmd`, `.sh`, etc.
- ✅ Bloquea tipos MIME peligrosos: ejecutables, scripts
- ⚡ **Velocidad**: Instantáneo (< 1ms)

#### 2️⃣ **Análisis Profundo de Contenido**
- 🔍 **Escaneo de Magic Numbers**: Busca firmas de archivos ocultos
- 🔍 **Detección de Archivos Comprimidos Ocultos**: ZIP, RAR, 7Z, GZIP
- 🔍 **Detección de Ejecutables**: EXE, ELF, Mach-O
- 🔍 **Análisis de Datos Finales**: Detecta archivos agregados al final (técnica común)
- 📊 **Análisis de Entropía**: Detecta contenido encriptado/comprimido oculto

### ¿Qué Detecta?

| Amenaza | Técnica | Detección |
|---------|---------|-----------|
| **Archivo ZIP en Imagen** | Magic number 0x504B0304 | ✅ Detectado |
| **Ejecutable Oculto** | Magic number 0x4D5A (MZ) | ✅ Bloqueado |
| **RAR en PDF** | Magic number 0x52617221 | ✅ Detectado |
| **Datos al Final de JPEG** | Bytes después de EOI (0xFFD9) | ✅ Detectado |
| **Datos al Final de PNG** | Bytes después de IEND | ✅ Detectado |
| **Contenido Encriptado** | Entropía > 7.5 bits/byte | ✅ Alerta |
| **Extensión Falsa** | .jpg.exe renombrado a .jpg | ✅ Detectado por contenido |

## 🔬 Técnicas de Detección

### 1. Magic Numbers (Firmas de Archivo)
Cada tipo de archivo tiene una "firma" única en sus primeros bytes:

```
JPEG:  FF D8 FF
PNG:   89 50 4E 47
ZIP:   50 4B 03 04
RAR:   52 61 72 21
EXE:   4D 5A
PDF:   25 50 44 46
```

El sistema escanea **todo el archivo** buscando estas firmas en cualquier posición, no solo al inicio.

### 2. Análisis de Trailing Data
Técnica común: agregar un ZIP al final de una imagen

```
[IMAGEN JPEG VÁLIDA][EOF Marker: FF D9][ARCHIVO ZIP OCULTO]
                                       ↑
                                  Aquí detectamos
```

### 3. Análisis de Entropía
La entropía mide el "desorden" de los datos:
- **Texto plano**: ~4-5 bits/byte
- **Imagen normal**: ~6-7 bits/byte  
- **Datos encriptados/comprimidos**: ~7.5-8 bits/byte ⚠️

Si una imagen tiene entropía > 7.5, es sospechosa.

## 📋 Flujo de Validación

```
┌──────────────────────┐
│ Usuario sube archivo │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────┐
│ 1. Validación Rápida     │
│    - Extensión           │
│    - MIME type           │
└──────────┬───────────────┘
           │
           ├─► ❌ Peligroso → Eliminar archivo
           │
           ▼
┌──────────────────────────┐
│ 2. Análisis Profundo     │
│    - Escanear contenido  │
│    - Buscar magic numbers│
│    - Verificar trailing  │
│    - Calcular entropía   │
└──────────┬───────────────┘
           │
           ├─► ⛔ Sospechoso → Eliminar archivo + Log detallado
           │
           ▼
┌──────────────────────────┐
│ 3. Guardar en DB         │
│    - Encriptar metadata  │
│    - Generar mensaje     │
└──────────────────────────┘
```

## 🚨 Respuestas del Sistema

### Archivo Limpio
```json
{
  "safe": true,
  "detectedType": "JPEG",
  "entropy": "6.85",
  "hiddenFiles": [],
  "details": "Archivo seguro"
}
```

### Archivo con Esteganografía
```json
{
  "safe": false,
  "detectedType": "JPEG",
  "entropy": "7.82",
  "hiddenFiles": [
    {
      "type": "ZIP",
      "offset": 45234,
      "risk": "HIGH"
    }
  ],
  "trailingData": {
    "suspicious": true,
    "trailingBytes": 12450,
    "message": "Datos sospechosos después del fin de imagen JPEG"
  },
  "details": "🚨 ARCHIVOS COMPRIMIDOS OCULTOS: ZIP | ⚠️ Datos sospechosos después del fin de imagen JPEG (12450 bytes)"
}
```

## 🧪 Ejemplos de Ataques Bloqueados

### 1. Image + ZIP (Técnica "Polyglot")
```bash
# Atacante crea archivo con ambos formatos:
cat imagen.jpg archivo.zip > malicioso.jpg

# ✅ Sistema detecta:
# - Magic number ZIP en offset != 0
# - Trailing data después de JPEG EOI
# - Resultado: BLOQUEADO
```

### 2. Ejecutable Renombrado
```bash
# Atacante renombra virus.exe a foto.jpg

# ✅ Sistema detecta:
# - Magic number "MZ" (ejecutable)
# - MIME type no coincide con contenido
# - Resultado: BLOQUEADO
```

### 3. PDF con ZIP Embebido
```bash
# Atacante oculta ZIP dentro de PDF

# ✅ Sistema detecta:
# - Magic number ZIP en medio del archivo
# - Risk: HIGH
# - Resultado: BLOQUEADO
```

## 📊 Logs de Seguridad

### Archivo Bloqueado
```
⛔ ARCHIVO BLOQUEADO - Esteganografía detectada {
  "roomId": "673abc123def",
  "detectedType": "JPEG",
  "entropy": "7.82",
  "hiddenFiles": 1,
  "details": "🚨 ARCHIVOS COMPRIMIDOS OCULTOS: ZIP"
}
```

### Archivo Aprobado
```
✅ Archivo aprobado análisis de seguridad {
  "roomId": "673abc123def",
  "detectedType": "PNG",
  "entropy": "6.45"
}
```

## ⚙️ Configuración

### Ajustar Sensibilidad de Entropía
En `steganographyDetector.js`:

```javascript
// Más estricto (puede dar falsos positivos)
const highEntropy = entropy > 7.0;

// Menos estricto (actual)
const highEntropy = entropy > 7.5;

// Muy permisivo (no recomendado)
const highEntropy = entropy > 7.8;
```

### Agregar Nuevos Tipos Bloqueados
```javascript
const FILE_SIGNATURES = {
  // ... existentes
  SQLITE: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], // SQLite
  CLASS: [0xCA, 0xFE, 0xBA, 0xBE], // Java Class
};
```

## 🎯 Tipos de Archivo Permitidos

Por defecto, el sistema permite:
- ✅ Imágenes: JPEG, PNG, GIF, BMP, WEBP
- ✅ Audio: MP3, WAV, OGG (si se configuran)
- ✅ Video: MP4, WEBM (si se configuran)
- ✅ Documentos: PDF (con análisis)

**NO permite**:
- ❌ Ejecutables (.exe, .elf, .app, .bin)
- ❌ Scripts (.sh, .bat, .cmd, .vbs, .js)
- ❌ Archivos comprimidos nativos (ZIP, RAR, 7Z, TAR)
- ❌ Código fuente ejecutable (.jar, .deb, .rpm)

## 🔐 Seguridad Adicional

### Combinado con:
1. ✅ **Encriptación AES-256**: Archivos encriptados en base de datos
2. ✅ **Validación de entrada**: express-validator
3. ✅ **Sanitización XSS**: validator.escape
4. ✅ **Logging seguro**: Sin datos sensibles en logs
5. ✅ **Límite de tamaño**: 10MB máximo (configurable en multer)

## 📈 Rendimiento

| Operación | Tiempo |
|-----------|--------|
| Validación rápida | < 1ms |
| Escaneo completo (1MB) | ~50-100ms |
| Escaneo completo (10MB) | ~200-500ms |
| Cálculo de entropía | ~10-30ms |

## 🚀 Uso en Producción

### Recomendaciones:
1. **Limitar tamaño de archivo**: Máximo 10-20MB
2. **Timeout de escaneo**: 5 segundos máximo
3. **Rate limiting**: Máximo 10 archivos/minuto por usuario
4. **Cuarentena**: Guardar archivos sospechosos en carpeta separada para análisis
5. **Alertas**: Notificar al admin cuando se bloquea un archivo

### Monitoreo:
```javascript
// En logs buscar:
"⛔ ARCHIVO BLOQUEADO - Esteganografía detectada"

// Revisar periódicamente archivos bloqueados
// Analizar patrones de ataque
```

## 🆘 Falsos Positivos

Es posible que archivos legítimos sean bloqueados si:
- Tienen muy alta compresión (entropía alta)
- Contienen datos binarios raros
- Fueron generados por software poco común

**Solución**: Agregar whitelist de hashes MD5 para archivos conocidos buenos.

## 📚 Referencias

- [Steganography Detection Techniques](https://en.wikipedia.org/wiki/Steganography)
- [File Signatures Database](https://www.garykessler.net/library/file_sigs.html)
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))

---

**Última actualización**: Noviembre 2025
**Estado**: ✅ Activo y funcionando
