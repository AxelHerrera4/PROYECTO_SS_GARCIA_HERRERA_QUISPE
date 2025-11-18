import Message from "../models/Message.js";
import Room from "../models/Room.js";
import BlockedUpload from "../models/BlockedUpload.js";
import { detectSteganography, quickValidation } from "../utils/steganographyDetector.js";
import fs from "fs";
import { secureLog, errorLog } from "../utils/logger.js";
import path from "path";
import { detectArchiveBomb } from "../utils/archiveBombDetector.js";


// Config: si UPLOAD_STRICT_MODE=false entonces sólo bloquear por problemas estructurales/cripto
const UPLOAD_STRICT_MODE = (process.env.UPLOAD_STRICT_MODE || 'true').toLowerCase() !== 'false';
export const uploadFile = async (req, res) => {
  try {
    const { roomId, sender } = req.body;
    const file = req.file;

    if (!file) {
      errorLog("No se recibió archivo", new Error("Missing file"));
      return res.status(400).json({ message: "No se recibió archivo" });
    }

    if (!roomId || !sender) {
      errorLog("Faltan datos obligatorios", new Error("Missing roomId or sender"));
      return res.status(400).json({ message: "Faltan datos obligatorios (roomId, sender)" });
    }

        //  PASO ZIP/RAR BOMB — ANTES DEL QUICK VALIDATION
    const archiveExt = path.extname(file.originalname || "").toLowerCase();

    if (archiveExt === ".zip" || archiveExt === ".rar") {
      secureLog("🔍 Analizando posible ZIP/RAR bomb", {
        roomId,
        filename: file.originalname,
      });

      const bomb = await detectArchiveBomb(file.path, archiveExt);

      if (bomb.isBomb) {
        try { fs.unlinkSync(file.path); } catch (e) {}

        secureLog(" Archivo bloqueado: ZIP/RAR BOMB detectado", {
          roomId,
          filename: file.originalname,
          stats: bomb.stats,
        });

        try {
          await BlockedUpload.create({
            originalName: file.originalname,
            storedFilename: file.filename,
            mimetype: file.mimetype,
            reason: `ZIP/RAR Bomb detected (${bomb.type})`,
            hiddenFiles: [bomb.stats],
            detectedType: bomb.type,
            room: roomId,
          });
        } catch (e) {
          // ignorar errores de BD
        }

        return res.status(403).json({
          message: "Archivo ZIP/RAR bloqueado (posible bomba de descompresión)",
          reasonType: "archive_bomb",
          details: bomb.stats,
        });
      }

      secureLog(" Archivo comprimido NO presenta comportamiento de bomba", {
        roomId,
        filename: file.originalname,
      });
    }


    // Protección adicional: rechazar si la extensión FINAL es peligrosa (ej. photo.jpg.exe será bloqueado)
    const blockedExts = ['.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.jar', '.sh'];
    const ext = (file.originalname || '').toLowerCase().match(/\.[^.]+$/)?.[0];
    if (ext && blockedExts.includes(ext)) {
      try { fs.unlinkSync(file.path); } catch (e) {}
      secureLog('⛔', 'Archivo bloqueado por extensión peligrosa en el nombre', { roomId, filename: file.originalname });
      // Guardar intento bloqueado
      try {
        await BlockedUpload.create({
          originalName: file.originalname,
          storedFilename: file.filename,
          mimetype: file.mimetype,
          reason: 'Extensión peligrosa en la extensión final',
          room: roomId
        });
      } catch (e) {
        // ignore DB errors
      }
      return res.status(403).json({ message: 'Archivo no permitido (extensión peligrosa detectada)', reasonType: 'extension' });
    }

    // 🔒 PASO 1: Validación rápida por extensión y MIME
    const quickCheck = quickValidation(file.mimetype, file.originalname);
    if (!quickCheck.safe) {
      // En modo estricto: bloquear como antes
      if (UPLOAD_STRICT_MODE) {
        try { fs.unlinkSync(file.path); } catch (e) {}
        secureLog("🚫", "Archivo bloqueado (validación rápida)", { 
          roomId, 
          mimetype: file.mimetype,
          reason: quickCheck.reason 
        });
        // Guardar intento bloqueado
        try {
          await BlockedUpload.create({
            originalName: file.originalname,
            storedFilename: file.filename,
            mimetype: file.mimetype,
            reason: `QuickValidation: ${quickCheck.reason}`,
            room: roomId
          });
        } catch (e) {}
        return res.status(403).json({ 
          message: "Archivo no permitido", 
          reason: quickCheck.reason,
          reasonType: 'quick_validation'
        });
      }

      // Modo "crypto-only": sólo advertimos y seguimos (no eliminar ni bloquear)
      secureLog("⚠️", "QuickValidation falló, permitiendo por modo crypto-only", {
        roomId,
        mimetype: file.mimetype,
        reason: quickCheck.reason
      });
    }

    // 🔒 PASO 2: Análisis profundo de esteganografía
    secureLog("🔍", "Analizando archivo por esteganografía", { roomId, mimetype: file.mimetype });
    const stegoAnalysis = await detectSteganography(file.path);
    
    // Decide bloqueo en base al modo
    let blockBecauseStego = false;
    if (!stegoAnalysis.safe) {
      if (UPLOAD_STRICT_MODE) {
        blockBecauseStego = true;
      } else {
          // Modo crypto-only: bloquear sólo si hay indicios estructurales fuertes
          const isCorrupted = !!stegoAnalysis.corrupted;
          const detectedExe = (stegoAnalysis.detectedType || '').toLowerCase().includes('exe') || (stegoAnalysis.detectedType || '').toLowerCase().includes('executable');
          // stegoAnalysis.hiddenFiles viene como array de objetos { type, offset, risk }
          // El chequeo anterior buscaba propiedades 'name' o strings y fallaba para objetos.
          const hiddenFiles = stegoAnalysis.hiddenFiles || [];
          const hiddenExe = hiddenFiles.some(hf => {
            const t = (hf.type || '').toString().toLowerCase();
            // Ejecutables o binarios embebidos
            if (t.includes('exe') || t.includes('elf') || t.includes('mach') || t.includes('executable')) return true;
            // Archivos comprimidos embebidos (alto riesgo si van después del contenedor)
            if (['zip','rar','7z'].includes(t)) return true;
            return false;
          });

          if (isCorrupted || detectedExe || hiddenExe) {
            blockBecauseStego = true;
          }
      }
    }

    if (blockBecauseStego) {
      // Eliminar archivo sospechoso
      try { fs.unlinkSync(file.path); } catch (e) {}
      secureLog("⛔", "ARCHIVO BLOQUEADO - Esteganografía detectada", {
        roomId,
        detectedType: stegoAnalysis.detectedType,
        entropy: stegoAnalysis.entropy,
        hiddenFiles: stegoAnalysis.hiddenFiles?.length || 0,
        corrupted: stegoAnalysis.corrupted || false,
        details: stegoAnalysis.details
      });
      // Guardar intento bloqueado con detalles de análisis
      try {
        await BlockedUpload.create({
          originalName: file.originalname,
          storedFilename: file.filename,
          mimetype: file.mimetype,
          reason: stegoAnalysis.details || 'Esteganografía detectada',
          detectedType: stegoAnalysis.detectedType,
          entropy: Number(stegoAnalysis.entropy) || undefined,
          hiddenFiles: stegoAnalysis.hiddenFiles || [],
          room: roomId
        });
      } catch (e) {}
      return res.status(403).json({ 
        message: "Archivo sospechoso bloqueado",
        reason: stegoAnalysis.corrupted 
          ? "El archivo está corrupto o tiene una estructura inválida"
          : "Se detectó contenido oculto o esteganografía en el archivo",
        details: stegoAnalysis.details,
        reasonType: 'steganography'
      });
    } else {
      // No bloqueado por estego en modo menos estricto: registrar advertencia
      if (!stegoAnalysis.safe) {
        secureLog("⚠️", "Esteganografía débil detectada pero permitida por modo crypto-only", {
          roomId,
          detectedType: stegoAnalysis.detectedType,
          entropy: stegoAnalysis.entropy,
          hiddenFiles: stegoAnalysis.hiddenFiles?.length || 0,
          corrupted: stegoAnalysis.corrupted || false,
          details: stegoAnalysis.details
        });
      }
    }
    
    // 🔒 PASO 3: Validar que el tipo MIME coincida con el contenido real
    const mimeTypeMap = {
      'JPEG': ['image/jpeg', 'image/jpg'],
      'PNG': ['image/png'],
      'GIF': ['image/gif'],
      'BMP': ['image/bmp'],
      'WEBP': ['image/webp'],
      'PDF': ['application/pdf']
    };
    
    const expectedMimes = mimeTypeMap[stegoAnalysis.detectedType] || [];
    if (expectedMimes.length > 0 && !expectedMimes.includes(file.mimetype)) {
      // En modo estricto: bloquear. En modo crypto-only: permitir pero registrar.
      if (UPLOAD_STRICT_MODE) {
        fs.unlinkSync(file.path);
        secureLog("⚠️", "MIME type no coincide con contenido", {
          roomId,
          declaredMime: file.mimetype,
          detectedType: stegoAnalysis.detectedType,
          expectedMimes: expectedMimes.join(', ')
        });
        return res.status(403).json({
          message: "Tipo de archivo no coincide",
          reason: `El archivo dice ser ${file.mimetype} pero su contenido es ${stegoAnalysis.detectedType}`,
          details: "Posible intento de falsificación de tipo de archivo"
        });
      } else {
        secureLog("⚠️", "MIME mismatch pero permitido por modo crypto-only", {
          roomId,
          declaredMime: file.mimetype,
          detectedType: stegoAnalysis.detectedType,
          expectedMimes: expectedMimes.join(', ')
        });
      }
    }

    secureLog("✅", "Archivo aprobado análisis de seguridad", { 
      roomId, 
      detectedType: stegoAnalysis.detectedType,
      entropy: stegoAnalysis.entropy 
    });

    // Confirmar datos sin información sensible
    secureLog("�", "Procesando archivo aprobado", { roomId, mimetype: file.mimetype });

    // Buscar sala
    const room = await Room.findById(roomId);
    if (!room) {
      fs.unlinkSync(file.path); // Limpiar archivo
      errorLog("Sala no encontrada", new Error("Room not found"), { roomId });
      return res.status(404).json({ message: "Sala no encontrada" });
    }

    // ✅ Validar que la sala sea multimedia
    if (room.type !== "multimedia") {
      fs.unlinkSync(file.path); // Limpiar archivo
      secureLog("⚠️", "Sala no permite archivos", { roomId, roomType: room.type });
      return res.status(403).json({ message: "Esta sala no permite archivos. Solo salas multimedia pueden compartir archivos." });
    }

    // Construir URL del archivo (ruta en server)
    const fileUrl = `/uploads/${file.filename}`;
    // Para evitar problemas de cache/latencia en volumes montados (Windows/Docker),
    // devolvemos al cliente una URL pública con un parámetro de cache-busting.
    const publicFileUrl = `${fileUrl}?t=${Date.now()}`;

    // Guardar mensaje en Mongo
    const message = new Message({
      room: roomId,
      sender,
      // Guardamos la ruta sin el parámetro de cache-busting en la BD
      content: fileUrl,
      type: "file",
    });

    await message.save();
    secureLog("✅", "Archivo guardado en base de datos", { 
      roomId, 
      mimetype: file.mimetype,
      messageId: message._id 
    });

    res.status(200).json({
      message: "Archivo subido correctamente",
      // Devolver la URL pública con cache-bust para que el navegador cargue la imagen inmediatamente
      fileUrl: publicFileUrl,
      fileName: file.originalname,
      messageId: message._id,
    });
  } catch (error) {
    // Limpiar archivo si hubo error
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        // Ignorar error de limpieza
      }
    }
    errorLog("Error al subir archivo", error, { roomId: req.body.roomId });
    res.status(500).json({ message: "Error al subir archivo", error: error.message });
  }
};
