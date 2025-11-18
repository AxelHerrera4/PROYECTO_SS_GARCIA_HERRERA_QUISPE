import express from "express";
import Room from "../models/Room.js";
import UserRoom from "../models/UserRoom.js";
import { protectAdmin } from "../middleware/authMiddleware.js";

const router = express.Router();

// 📦 Obtener todas las salas del usuario actual (si usas token, puedes filtrar por createdBy)
router.get("/", async (req, res) => {
  try {
    const rooms = await Room.find().sort({ createdAt: -1 });
    res.json(rooms);
  } catch (err) {
    console.error("Error al obtener salas:", err);
    res.status(500).json({ message: "Error al obtener salas" });
  }
});

// ✏️ Actualizar sala
router.put("/:id", async (req, res) => {
  try {
    const { name, type } = req.body;
    const room = await Room.findByIdAndUpdate(
      req.params.id,
      { name, type },
      { new: true }
    );
    if (!room) return res.status(404).json({ message: "Sala no encontrada" });
    res.json({ message: "Sala actualizada correctamente", room });
  } catch (err) {
    console.error("Error al actualizar sala:", err);
    res.status(500).json({ message: "Error al actualizar sala" });
  }
});

// 🗑️ Eliminar sala
router.delete("/:id", async (req, res) => {
  try {
    const deleted = await Room.findByIdAndDelete(req.params.id);
    if (!deleted)
      return res.status(404).json({ message: "Sala no encontrada" });
    res.json({ message: "Sala eliminada correctamente" });
  } catch (err) {
    console.error("Error al eliminar sala:", err);
    res.status(500).json({ message: "Error al eliminar sala" });
  }
});

// 🔎 Obtener participantes de una sala (solo admin)
router.get("/:id/participants", protectAdmin, async (req, res) => {
  try {
    const roomId = req.params.id;
    const participants = await UserRoom.find({ room: roomId }).select("nickname joinedAt -_id");
    res.json(participants);
  } catch (err) {
    console.error("Error al obtener participantes:", err);
    res.status(500).json({ message: "Error al obtener participantes" });
  }
});

// 🛑 Obtener intentos de subida bloqueados para una sala (solo admin)
router.get("/:id/uploads/blocked", protectAdmin, async (req, res) => {
  try {
    const roomId = req.params.id;
    const BlockedUpload = await import("../models/BlockedUpload.js");
    const docs = await BlockedUpload.default.find({ room: roomId }).sort({ createdAt: -1 }).limit(200);
    res.json(docs);
  } catch (err) {
    console.error("Error al obtener uploads bloqueados:", err);
    res.status(500).json({ message: "Error al obtener uploads bloqueados" });
  }
});

export default router;
