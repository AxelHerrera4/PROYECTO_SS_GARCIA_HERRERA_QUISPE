import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
// import mongoSanitize from "express-mongo-sanitize"; // Temporalmente desactivado por conflicto
import adminRoutes from "./routes/adminRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import messageRoutes from "./routes/messageRoutes.js";
import fileRoutes from "./routes/fileRoutes.js";
import roomRoutes from "./routes/roomRoutes.js";
import path from "path";
import authRoutes from "./routes/authRoutes.js";
import roomAdminRoutes from "./routes/roomAdminRoutes.js";
import { sanitizeObject } from './utils/sanitizer.js';

dotenv.config();

const app = express();

// 🛡️ Configuración de CORS (debe ir PRIMERO)
// Proteger contra ausencia o formato inesperado de la variable de entorno
const rawClientOrigin = process.env.CLIENT_ORIGIN || "http://localhost:5173";
const allowedOrigins = rawClientOrigin
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Permitir solicitudes sin origin (como Postman) o las del array
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('No permitido por CORS'));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    preflightContinue: false,
    optionsSuccessStatus: 204
  })
);

// 🛡️ Middlewares de seguridad
// Helmet - Protección de headers HTTP (DESPUÉS de CORS)
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false, // Desactivar CSP para desarrollo
}));

// ⚠️ Nota: express-mongo-sanitize desactivado temporalmente por conflicto con Node 22
// La protección contra inyección NoSQL está cubierta por express-validator
// que valida y sanitiza todos los inputs antes de llegar a MongoDB

// Limitar tamaño de payload para prevenir ataques DoS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Sanitizar entrantes para mitigar XSS/NoSQL injection (capa ligera)
app.use((req, res, next) => {
  try {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.params) req.params = sanitizeObject(req.params);
    if (req.query) req.query = sanitizeObject(req.query);
  } catch (e) {
    // no bloquear por errores de sanitización
  }
  next();
});

// Ruta de prueba
app.get("/", (req, res) => {
  res.json({ message: "Servidor de Chat en Tiempo Real funcionando" });
});

app.use("/api/admin", adminRoutes);
app.use("/api/users", userRoutes);
app.use("/api/messages", messageRoutes);
// Servir archivos estáticos desde /uploads
app.use("/uploads", express.static("uploads"));
app.use("/api/files", fileRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/rooms", roomRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/admin/rooms", roomAdminRoutes);



export default app;
