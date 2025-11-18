import express from "express";
import { 
  registerAdmin, 
  loginAdmin, 
  getMyRooms, 
  updateRoom, 
  deleteRoom 
} from "../controllers/adminController.js";
import { getDownloads } from "../controllers/downloadController.js";
import { protectAdmin } from "../middleware/authMiddleware.js";
import { 
  validateUpdateRoom, 
  validateMongoId 
} from "../middleware/validators.js";

const router = express.Router();

// Registrar nuevo admin
router.post("/register", registerAdmin);

// Iniciar sesión
router.post("/login", loginAdmin);

// Obtener mis salas creadas (requiere autenticación de admin)
router.get("/rooms", protectAdmin, getMyRooms);

// Obtener registros de descargas (admin)
router.get('/downloads', protectAdmin, getDownloads);

// Actualizar sala (requiere autenticación de admin)
router.put("/rooms/:id", protectAdmin, validateMongoId, validateUpdateRoom, updateRoom);

// Eliminar sala (requiere autenticación de admin)
router.delete("/rooms/:id", protectAdmin, validateMongoId, deleteRoom);

export default router;
