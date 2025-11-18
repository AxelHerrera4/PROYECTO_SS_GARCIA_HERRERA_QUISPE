import express from "express";
import { deleteMessage, editMessage, getRoomMessages } from "../controllers/messageController.js";
import { protect, protectAny } from "../middleware/authMiddleware.js";
import mongoose from 'mongoose';
import { validateMongoId } from "../middleware/validators.js";
import { errorLog } from "../utils/logger.js";

const router = express.Router();

// Obtener mensajes de una sala (soporta user o admin)
// Validate roomId param to avoid invalid input
router.get("/room/:roomId", protectAny, (req, res, next) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.roomId)) {
    return res.status(400).json({ message: 'ID de sala inválido' });
  }
  next();
}, getRoomMessages);

// Eliminar mensaje (requiere autenticación de usuario/admin apropiado)
router.delete("/:id", protect, validateMongoId, deleteMessage);

// Editar mensaje (requiere autenticación de usuario)
router.put("/:id", protect, validateMongoId, editMessage);

export default router;
