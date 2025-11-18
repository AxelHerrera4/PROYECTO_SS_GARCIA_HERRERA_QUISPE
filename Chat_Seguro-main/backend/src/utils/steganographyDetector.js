// steganographyDetector.js - Detecta archivos con esteganografía
import fs from 'fs';

/**
 * Firmas de archivos (magic numbers) para detectar archivos ocultos
 */
const FILE_SIGNATURES = {
  // Archivos comprimidos
  ZIP: [0x50, 0x4B, 0x03, 0x04], // PK..
  RAR: [0x52, 0x61, 0x72, 0x21], // Rar!
  '7Z': [0x37, 0x7A, 0xBC, 0xAF], // 7z
  GZIP: [0x1F, 0x8B],
  TAR: [0x75, 0x73, 0x74, 0x61, 0x72], // ustar (offset 257)
  
  // Ejecutables
  EXE: [0x4D, 0x5A], // MZ
  ELF: [0x7F, 0x45, 0x4C, 0x46], // .ELF
  MACH_O: [0xFE, 0xED, 0xFA, 0xCE], // Mach-O
  
  // Documentos
  PDF: [0x25, 0x50, 0x44, 0x46], // %PDF
  DOC: [0xD0, 0xCF, 0x11, 0xE0], // Office docs
  
  // Imágenes (para referencia)
  JPEG: [0xFF, 0xD8, 0xFF],
  PNG: [0x89, 0x50, 0x4E, 0x47],
  GIF: [0x47, 0x49, 0x46, 0x38],
  BMP: [0x42, 0x4D],
  WEBP: [0x52, 0x49, 0x46, 0x46], // RIFF
};

/**
 * Detecta posibles datos ocultos en los bits menos significativos (LSB) de la imagen
 * usando la librería 'sharp' para obtener los píxeles en crudo. Devuelve un objeto
 * con indicios si encuentra firmas o alta entropía en el flujo reconstruido.
 */
const detectLSBUsingSharp = async (filePath, maxPixels = 200000) => {
  try {
    // Import dinámico de sharp (si no está instalado, lanzar error controlado)
    let sharp;
    try {
      sharp = (await import('sharp')).default;
    } catch (e) {
      throw new Error('sharp-no-present');
    }

    // Obtener buffer crudo RGBA
    const img = sharp(filePath).ensureAlpha();
    const { data, info } = await img.raw().toBuffer({ resolveWithObject: true });
    const channels = info.channels || 4;
    const totalPixels = Math.floor(data.length / channels);
    const pixelsToUse = Math.min(totalPixels, maxPixels);

    // Extraer bits LSB de los primeros pixelsToUse pixels
    const bits = [];
    const bytesApprox = Math.floor((pixelsToUse * channels) / 8);
    for (let i = 0; i < pixelsToUse * channels; i++) {
      bits.push(data[i] & 1);
    }

    // Construir bytes a partir de bits (MSB-first)
    const outBytes = [];
    for (let i = 0; i + 7 < bits.length; i += 8) {
      let val = 0;
      for (let b = 0; b < 8; b++) {
        val = (val << 1) | bits[i + b];
      }
      outBytes.push(val);
    }

    const outBuf = Buffer.from(outBytes);

    // Calcular entropía del stream LSB
    const lsbEntropy = calculateEntropy(outBuf);

    // Buscar firmas conocidas en el flujo reconstruido
    const signaturesFound = [];
    const searchLimit = Math.min(outBuf.length, 500000);
    for (let i = 0; i < searchLimit - 4; i++) {
      if (matchesSignature(outBuf, FILE_SIGNATURES.ZIP, i)) signaturesFound.push({ type: 'ZIP', offset: i });
      if (matchesSignature(outBuf, FILE_SIGNATURES.RAR, i)) signaturesFound.push({ type: 'RAR', offset: i });
      if (matchesSignature(outBuf, FILE_SIGNATURES['7Z'], i)) signaturesFound.push({ type: '7Z', offset: i });
      if (matchesSignature(outBuf, FILE_SIGNATURES.EXE, i)) signaturesFound.push({ type: 'EXE', offset: i });
      if (matchesSignature(outBuf, FILE_SIGNATURES.PDF, i)) signaturesFound.push({ type: 'PDF', offset: i });
    }

    const suspicious = signaturesFound.length > 0 || lsbEntropy > 7.5;

    return {
      suspicious,
      lsbEntropy: lsbEntropy.toFixed(2),
      signaturesFound,
      reason: signaturesFound.length > 0 ? `Firmas: ${signaturesFound.map(s=>s.type).join(',')}` : (lsbEntropy > 7.5 ? 'Alta entropía en LSB' : null)
    };
  } catch (err) {
    // Propagar error para ser manejado por el caller
    throw err;
  }
};

/**
 * Compara bytes con una firma
 */
const matchesSignature = (buffer, signature, offset = 0) => {
  for (let i = 0; i < signature.length; i++) {
    if (buffer[offset + i] !== signature[i]) {
      return false;
    }
  }
  return true;
};

/**
 * Busca firmas de archivos ocultos en todo el buffer
 * @param {Buffer} buffer - Contenido del archivo
 * @returns {Array} - Array de detecciones encontradas
 */
const scanForHiddenFiles = (buffer) => {
  const detections = [];
  const scanLength = Math.min(buffer.length, 10 * 1024 * 1024); // Escanear hasta 10MB
  
  // Buscar firmas de archivos peligrosos en todo el buffer
  for (let i = 0; i < scanLength - 4; i++) {
    // Archivos comprimidos
    if (matchesSignature(buffer, FILE_SIGNATURES.ZIP, i)) {
      detections.push({ type: 'ZIP', offset: i, risk: 'HIGH' });
    }
    if (matchesSignature(buffer, FILE_SIGNATURES.RAR, i)) {
      detections.push({ type: 'RAR', offset: i, risk: 'HIGH' });
    }
    if (matchesSignature(buffer, FILE_SIGNATURES['7Z'], i)) {
      detections.push({ type: '7Z', offset: i, risk: 'HIGH' });
    }
    
    // Ejecutables: marcar detecciones en cualquier offset como CRITICAL
    // (esto detecta casos donde un ejecutable fue concatenado/embebido en un archivo legítimo)
    if (matchesSignature(buffer, FILE_SIGNATURES.EXE, i)) {
      detections.push({ type: 'EXE', offset: i, risk: 'CRITICAL' });
    }
    if (matchesSignature(buffer, FILE_SIGNATURES.ELF, i)) {
      detections.push({ type: 'ELF', offset: i, risk: 'CRITICAL' });
    }
    
    // PDFs ocultos
    if (matchesSignature(buffer, FILE_SIGNATURES.PDF, i)) {
      detections.push({ type: 'PDF', offset: i, risk: 'MEDIUM' });
    }
  }
  
  return detections;
};

/**
 * Detecta el tipo real del archivo por su contenido
 */
const detectFileType = (buffer) => {
  if (matchesSignature(buffer, FILE_SIGNATURES.JPEG)) return 'JPEG';
  if (matchesSignature(buffer, FILE_SIGNATURES.PNG)) return 'PNG';
  if (matchesSignature(buffer, FILE_SIGNATURES.GIF)) return 'GIF';
  if (matchesSignature(buffer, FILE_SIGNATURES.BMP)) return 'BMP';
  if (matchesSignature(buffer, FILE_SIGNATURES.WEBP)) return 'WEBP';
  if (matchesSignature(buffer, FILE_SIGNATURES.PDF)) return 'PDF';
  if (matchesSignature(buffer, FILE_SIGNATURES.ZIP)) return 'ZIP';
  if (matchesSignature(buffer, FILE_SIGNATURES.RAR)) return 'RAR';
  if (matchesSignature(buffer, FILE_SIGNATURES['7Z'])) return '7Z';
  if (matchesSignature(buffer, FILE_SIGNATURES.EXE)) return 'EXE';
  if (matchesSignature(buffer, FILE_SIGNATURES.ELF)) return 'ELF';
  
  return 'UNKNOWN';
};

/**
 * Analiza la entropía del archivo (archivos con esteganografía suelen tener alta entropía)
 */
const calculateEntropy = (buffer) => {
  const frequencies = new Array(256).fill(0);
  const sampleSize = Math.min(buffer.length, 100000); // Analizar primeros 100KB
  
  for (let i = 0; i < sampleSize; i++) {
    frequencies[buffer[i]]++;
  }
  
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const probability = frequencies[i] / sampleSize;
      entropy -= probability * Math.log2(probability);
    }
  }
  
  return entropy;
};

/**
 * Analiza la entropía en ventanas deslizantes para detectar regiones de alta entropía
 * que pueden indicar datos ocultos (LSB o regiones comprimidas/encriptadas).
 */
const slidingWindowEntropy = (buffer, windowSize = 4096, step = 1024, threshold = 7.5) => {
  const limit = Math.min(buffer.length, 20 * 1024 * 1024); // no analizar >20MB
  for (let start = 0; start + windowSize <= limit; start += step) {
    const slice = buffer.slice(start, start + windowSize);
    const ent = calculateEntropy(slice);
    if (ent > threshold) {
      return { suspicious: true, offset: start, entropy: ent };
    }
  }
  return { suspicious: false };
};

/**
 * Inspecciona chunks de PNG buscando chunks auxiliares inusualmente grandes
 * que puedan contener datos ocultos.
 */
const inspectPNGChunks = (buffer) => {
  const results = [];
  // PNG signature + first 8 bytes already validated en validatePNG
  let pos = 8;
  while (pos + 8 < buffer.length) {
    // chunk length (4 bytes big-endian)
    const length = buffer.readUInt32BE(pos);
    const type = buffer.toString('ascii', pos + 4, pos + 8);
    // sanity
    if (isNaN(length) || length < 0 || pos + 12 + length > buffer.length) break;
    // marcar chunks auxiliares con tamaño sospechoso (>5KB)
    const ancillary = type[0] && type[0] === type[0].toLowerCase();
    if (ancillary && length > 5 * 1024) {
      results.push({ type, length, offset: pos });
    }
    pos += 12 + length; // length(4) + type(4) + data(length) + crc(4)
  }
  return results;
};

/**
 * Verifica si hay datos sospechosos al final del archivo
 * (técnica común: agregar archivo ZIP al final de una imagen)
 */
const checkTrailingData = (buffer, declaredType) => {
  const imageTypes = ['JPEG', 'PNG', 'GIF', 'BMP', 'WEBP'];
  if (!imageTypes.includes(declaredType)) return null;

  // Para JPEG: Es cierto que puede haber "trailing garbage" después del marcador EOI (FF D9),
  // pero también es una técnica común para ocultar archivos (append). Aquí intentamos
  // detectar firmas conocidas (ZIP/RAR/7Z/EXE/ELF/PDF) después del EOI y marcar como
  // sospechoso si se encuentran datos significativos.
  if (declaredType === 'JPEG') {
    // Buscar marcador EOI (FF D9) desde el final
    let eoiPos = -1;
    for (let i = buffer.length - 2; i >= 0; i--) {
      if (buffer[i] === 0xFF && buffer[i + 1] === 0xD9) {
        eoiPos = i + 2; // posición después de EOI
        break;
      }
    }

    if (eoiPos !== -1 && eoiPos < buffer.length) {
      const trailingBytes = buffer.length - eoiPos;
      // Escanear los primeros 1MB posteriores al EOI o hasta el final
      const scanEnd = Math.min(buffer.length, eoiPos + Math.min(trailingBytes, 1024 * 1024));
      for (let j = eoiPos; j < scanEnd - 4; j++) {
        if (matchesSignature(buffer, FILE_SIGNATURES.ZIP, j) || matchesSignature(buffer, FILE_SIGNATURES.RAR, j) || matchesSignature(buffer, FILE_SIGNATURES['7Z'], j) ) {
          return {
            suspicious: true,
            trailingBytes,
            message: 'Datos sospechosos agregados después del fin de imagen JPEG (posible archivo embebido)'
          };
        }
        if (matchesSignature(buffer, FILE_SIGNATURES.EXE, j) || matchesSignature(buffer, FILE_SIGNATURES.ELF, j)) {
          return {
            suspicious: true,
            trailingBytes,
            message: 'Ejecutable embebido detectado después del EOF de JPEG'
          };
        }
        if (matchesSignature(buffer, FILE_SIGNATURES.PDF, j)) {
          return {
            suspicious: true,
            trailingBytes,
            message: 'PDF detectado después del EOF de JPEG (posible archivo oculto)'
          };
        }
      }
      // Si hay muchos bytes extra sin firmas específicas, considerarlo sospechoso
      // sólo si es una cantidad significativa (ej. > 10KB). Esto reduce falsos
      // positivos con algunos encoders/metadata que añaden pequeños trailers.
      if (trailingBytes > 10 * 1024) {
        return {
          suspicious: true,
          trailingBytes,
          message: 'Datos extra significativos después del fin de imagen JPEG'
        };
      }
    }

    return null;
  }

  // Para PNG: buscar después del chunk IEND
  if (declaredType === 'PNG') {
    const iendSignature = [0x49, 0x45, 0x4E, 0x44]; // IEND chunk (solo los primeros 4 bytes)
    // Buscar el último chunk IEND válido
    let iendPosition = -1;
    for (let i = buffer.length - 12; i >= 8; i--) {
      if (matchesSignature(buffer, iendSignature, i)) {
        iendPosition = i;
        break;
      }
    }

    if (iendPosition !== -1) {
      const trailingBytes = buffer.length - iendPosition - 12; // 12 = tamaño del chunk IEND completo
      if (trailingBytes > 1024) { // Solo marcar como sospechoso si hay más de 1KB de datos extra
        return {
          suspicious: true,
          trailingBytes,
          message: 'Datos sospechosos después del fin de imagen PNG'
        };
      }
    }
  }

  return null;
};

/**
 * Valida la estructura completa del archivo según su tipo
 * @param {Buffer} buffer - Contenido del archivo
 * @param {string} detectedType - Tipo detectado
 * @returns {Object} - Resultado de validación
 */
const validateFileStructure = (buffer, detectedType) => {
  try {
    switch (detectedType) {
      case 'JPEG':
        return validateJPEG(buffer);
      case 'PNG':
        return validatePNG(buffer);
      case 'GIF':
        return validateGIF(buffer);
      default:
        return { valid: true };
    }
  } catch (error) {
    return { valid: false, reason: 'Error al validar estructura del archivo' };
  }
};

/**
 * Valida estructura JPEG completa
 */
const validateJPEG = (buffer) => {
  // JPEG debe empezar con FF D8 FF
  if (!matchesSignature(buffer, FILE_SIGNATURES.JPEG)) {
    return { valid: false, reason: 'Firma JPEG inválida' };
  }
  
  // JPEG debe terminar con EOI marker (FF D9)
  const lastTwo = buffer.slice(-2);
  if (lastTwo[0] !== 0xFF || lastTwo[1] !== 0xD9) {
    return { valid: false, reason: 'JPEG no tiene marcador de fin válido (EOI)' };
  }
  
  // Buscar marcadores JPEG válidos
  let validMarkers = 0;
  for (let i = 0; i < buffer.length - 1; i++) {
    if (buffer[i] === 0xFF && buffer[i + 1] !== 0x00 && buffer[i + 1] !== 0xFF) {
      validMarkers++;
    }
  }
  
  if (validMarkers < 3) {
    return { valid: false, reason: 'JPEG con estructura corrupta (marcadores insuficientes)' };
  }
  
  return { valid: true };
};

/**
 * Valida estructura PNG completa
 */
const validatePNG = (buffer) => {
  // PNG signature: 89 50 4E 47 0D 0A 1A 0A
  const pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  if (!matchesSignature(buffer, pngSignature)) {
    return { valid: false, reason: 'Firma PNG inválida' };
  }
  
  // Buscar chunk IHDR (debe ser el primero después de la firma)
  const ihdrPos = 8; // Justo después de la firma
  const ihdrSignature = [0x49, 0x48, 0x44, 0x52]; // IHDR
  if (!matchesSignature(buffer, ihdrSignature, ihdrPos + 4)) {
    return { valid: false, reason: 'PNG sin chunk IHDR válido' };
  }
  
  // Buscar chunk IEND (debe existir al final)
  const iendSignature = [0x49, 0x45, 0x4E, 0x44]; // IEND
  let hasIEND = false;
  for (let i = buffer.length - 12; i >= 0 && i > buffer.length - 100; i--) {
    if (matchesSignature(buffer, iendSignature, i)) {
      hasIEND = true;
      break;
    }
  }
  
  if (!hasIEND) {
    return { valid: false, reason: 'PNG sin chunk IEND (corrupto)' };
  }
  
  return { valid: true };
};

/**
 * Valida estructura GIF
 */
const validateGIF = (buffer) => {
  // GIF87a o GIF89a
  const gif87 = [0x47, 0x49, 0x46, 0x38, 0x37, 0x61];
  const gif89 = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61];
  
  if (!matchesSignature(buffer, gif87) && !matchesSignature(buffer, gif89)) {
    return { valid: false, reason: 'Firma GIF inválida' };
  }
  
  // GIF debe terminar con trailer (0x3B)
  if (buffer[buffer.length - 1] !== 0x3B) {
    return { valid: false, reason: 'GIF sin trailer válido (corrupto)' };
  }
  
  return { valid: true };
};

/**
 * Función principal de detección de esteganografía
 * @param {string} filePath - Ruta del archivo a analizar
 * @returns {Object} - Resultado del análisis
 */
export const detectSteganography = async (filePath) => {
  try {
    const buffer = fs.readFileSync(filePath);
    
    // Validar tamaño mínimo
    if (buffer.length < 12) {
      return {
        safe: false,
        detectedType: 'UNKNOWN',
        details: '⚠️ Archivo demasiado pequeño o vacío'
      };
    }
    
    const detectedType = detectFileType(buffer);
    
    // Rechazar archivos de tipo desconocido
    if (detectedType === 'UNKNOWN') {
      return {
        safe: false,
        detectedType: 'UNKNOWN',
        details: '⚠️ Tipo de archivo no reconocido o corrupto'
      };
    }
    
    const entropy = calculateEntropy(buffer);
    
    // 0. Validar estructura del archivo (detectar corrupción)
    const structureValidation = validateFileStructure(buffer, detectedType);
    if (!structureValidation.valid) {
      return {
        safe: false,
        detectedType,
        corrupted: true,
        details: `⚠️ ARCHIVO CORRUPTO: ${structureValidation.reason}`
      };
    }
    
    // 1. Buscar archivos ocultos
    const hiddenFiles = scanForHiddenFiles(buffer);
    
    // Filtrar la primera detección si coincide con el tipo de archivo
    // (para evitar falsos positivos con archivos ZIP legítimos)
    const suspiciousFiles = hiddenFiles.filter(detection => {
      // Si es la primera detección (offset 0) y coincide con el tipo, ignorar
      if (detection.offset === 0 && detection.type === detectedType) {
        return false;
      }
      return true;
    });
    
    // 2. Verificar datos al final del archivo
    const trailingData = checkTrailingData(buffer, detectedType);
    
    // 3. Analizar entropía global (valores muy altos = posible encriptación/compresión oculta)
    const highEntropy = entropy > 8.0; // Umbral global de entropía sospechosa

    // 3b. Analizar entropía por ventanas para detectar regiones locales de alta entropía
    const windowResult = slidingWindowEntropy(buffer);

    // 3c. Para PNGs, inspeccionar chunks auxiliares inusuales
    const pngChunks = detectedType === 'PNG' ? inspectPNGChunks(buffer) : [];
    
    // Determinar si el archivo es sospechoso
    // Solo considerar archivos con riesgo CRÍTICO o HIGH como sospechosos
    const criticalFiles = suspiciousFiles.filter(f => f.risk === 'CRITICAL');
    const highRiskFiles = suspiciousFiles.filter(f => f.risk === 'HIGH');

    const isSuspicious = criticalFiles.length > 0 ||
              highRiskFiles.length > 0 ||
              (trailingData && trailingData.suspicious) ||
              (highEntropy && detectedType !== 'ZIP' && detectedType !== 'RAR') ||
              (windowResult.suspicious) ||
              (pngChunks && pngChunks.length > 0);
    
    const detailsArray = [];
    // 4. Análisis LSB usando 'sharp' para imágenes razonables (más costoso)
    let lsbResult = null;
    try {
      const imageTypes = ['JPEG','PNG','GIF','WEBP','BMP'];
      // Ejecutar LSB si es imagen y no muy grande (ej. < 5MB) o si ya hay sospecha
      if ((imageTypes.includes(detectedType) && buffer.length <= 5 * 1024 * 1024) || windowResult.suspicious || highEntropy || (trailingData && trailingData.suspicious) || (pngChunks && pngChunks.length > 0)) {
        lsbResult = await detectLSBUsingSharp(filePath);
        if (lsbResult && lsbResult.suspicious) {
          // aumentar el nivel de sospecha
          detailsArray.push(`LSB sospechoso: ${lsbResult.reason || 'alta entropía / firma detectada'}`);
        }
      }
    } catch (e) {
      // no bloquear si sharp no está disponible o falla; solo loguear
      // console.warn('LSB analysis failed', e);
    }
    if (suspiciousFiles.length) detailsArray.push(...suspiciousFiles.map(f => `${f.type}@${f.offset}`));
    if (trailingData && trailingData.suspicious) detailsArray.push(trailingData.message);
    if (windowResult.suspicious) detailsArray.push(`Región de alta entropía en offset ${windowResult.offset} (entropía=${windowResult.entropy.toFixed(2)})`);
    if (pngChunks && pngChunks.length) detailsArray.push(`Chunks PNG inusuales: ${pngChunks.map(c=>`${c.type}:${c.length}`).join(', ')}`);

    // Considerar LSB como evidencia final si detectó algo
    const finalSuspicious = isSuspicious || (lsbResult && lsbResult.suspicious);

    if (suspiciousFiles.length) detailsArray.push(...suspiciousFiles.map(f => `${f.type}@${f.offset}`));
    if (trailingData && trailingData.suspicious) detailsArray.push(trailingData.message);
    if (windowResult.suspicious) detailsArray.push(`Región de alta entropía en offset ${windowResult.offset} (entropía=${windowResult.entropy.toFixed(2)})`);
    if (pngChunks && pngChunks.length) detailsArray.push(`Chunks PNG inusuales: ${pngChunks.map(c=>`${c.type}:${c.length}`).join(', ')}`);
    if (lsbResult) detailsArray.push(`LSB: entropy=${lsbResult.lsbEntropy}${lsbResult.signaturesFound?.length ? ' signatures='+lsbResult.signaturesFound.map(s=>s.type).join(',') : ''}`);

    return {
      safe: !finalSuspicious,
      detectedType,
      entropy: entropy.toFixed(2),
      hiddenFiles: suspiciousFiles,
      trailingData,
      highEntropy,
      highEntropyWindow: windowResult.suspicious ? windowResult : null,
      pngSuspiciousChunks: pngChunks,
      lsbResult,
      fileSize: buffer.length,
      details: finalSuspicious ? (detailsArray.join(' | ') || buildWarningMessage(suspiciousFiles, trailingData, highEntropy)) : 'Archivo seguro'
    };
    
  } catch (error) {
    return {
      safe: false,
      error: error.message,
      details: 'Error al analizar el archivo'
    };
  }
};

/**
 * Construye mensaje de advertencia detallado
 */
const buildWarningMessage = (hiddenFiles, trailingData, highEntropy) => {
  const warnings = [];
  
  if (hiddenFiles.length > 0) {
    const critical = hiddenFiles.filter(f => f.risk === 'CRITICAL');
    const high = hiddenFiles.filter(f => f.risk === 'HIGH');
    
    if (critical.length > 0) {
      warnings.push(`⛔ EJECUTABLES DETECTADOS: ${critical.map(f => f.type).join(', ')}`);
    }
    if (high.length > 0) {
      warnings.push(`🚨 ARCHIVOS COMPRIMIDOS OCULTOS: ${high.map(f => f.type).join(', ')}`);
    }
  }
  
  if (trailingData && trailingData.suspicious) {
    warnings.push(`⚠️ ${trailingData.message} (${trailingData.trailingBytes} bytes)`);
  }
  
  if (highEntropy) {
    warnings.push('📊 Entropía anormalmente alta (posible encriptación oculta)');
  }
  
  return warnings.join(' | ');
};

/**
 * Validación rápida solo por extensión y tipo MIME
 * (usar como pre-filtro antes del análisis profundo)
 */
export const quickValidation = (mimetype, filename) => {
  const dangerousExtensions = [
    '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.jar',
    '.app', '.deb', '.rpm', '.sh', '.bash', '.elf', '.bin'
  ];
  
  // Revisar solo la extensión final del nombre de archivo
  const ext = (filename || '').toLowerCase().match(/\.[^.]+$/)?.[0];
  if (ext && dangerousExtensions.includes(ext)) {
    return {
      safe: false,
      reason: 'Extensión de archivo no permitida'
    };
  }
  
  // Bloquear tipos MIME peligrosos
  const dangerousMimes = [
    'application/x-msdownload',
    'application/x-executable',
    'application/x-sh',
    'application/x-bat',
    'text/x-sh'
  ];
  
  if (dangerousMimes.includes(mimetype)) {
    return {
      safe: false,
      reason: 'Tipo de archivo no permitido'
    };
  }
  
  return { safe: true };
};
