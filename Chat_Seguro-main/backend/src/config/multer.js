import multer from "multer";
import path from "path";
import { secureLog } from "../utils/logger.js";
import fs from "fs";

// Crear carpeta si no existe
const uploadDir = "uploads";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  },
});

// ✅ Filtro más flexible para diversos tipos de archivo
const fileFilter = (req, file, cb) => {
  const allowedExts = [
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",  // Imágenes
    ".mp4", ".webm", ".mov", ".avi",                    // Videos
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",          // Documentos
    ".zip", ".rar", ".7z",                              // Archivos comprimidos
    ".mp3", ".wav", ".ogg",                             // Audio
    ".txt", ".json", ".csv"                             // Texto
  ];
  const ext = path.extname(file.originalname).toLowerCase();

  if (allowedExts.includes(ext)) {
    cb(null, true);
  } else {
    console.log("❌ Tipo de archivo no permitido:", file.originalname, ext);
    cb(new Error(`Tipo de archivo no permitido: ${ext}`), false);
  }
};

// Límite de tamaño (10 MB) - ajustado por requisitos de la app
export const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 },
});
