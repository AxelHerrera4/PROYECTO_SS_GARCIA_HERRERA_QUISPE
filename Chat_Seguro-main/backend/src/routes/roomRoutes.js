// routes/roomRoutes.js
import express from "express";
import Room from "../models/Room.js";
import { protectAny } from "../middleware/authMiddleware.js";
import { 
  validateCreateRoom, 
  validatePin 
} from "../middleware/validators.js";
import crypto from "crypto";

const router = express.Router();

// Crear nueva sala
router.post("/", protectAny, validateCreateRoom, async (req, res) => {
  try {
    console.log("🔵 POST /api/rooms - Body recibido:", req.body);
    const { name, type, pin } = req.body;
    const roomPin =
      pin && pin.trim() !== "" ? pin : crypto.randomInt(1000, 9999).toString();

    const existing = await Room.findOne({ pin: roomPin });
    if (existing)
      return res.status(400).json({ message: "Ya existe una sala con ese PIN" });

    const room = await Room.create({
      name,
      type,
      pin: roomPin,
      createdBy: req.user._id,
    });

    res.status(201).json({ message: "Sala creada correctamente", room });
  } catch (err) {
    console.error("Error al crear sala:", err);
    res.status(500).json({ message: "Error al crear sala", error: err.message });
  }
});

// Obtener todas las salas
router.get("/", async (req, res) => {
  try {
    const rooms = await Room.find().populate("createdBy");
    res.json(rooms);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener salas" });
  }
});

// Obtener una sala específica
router.get("/:id", async (req, res) => {
  try {
    const room = await Room.findById(req.params.id).populate("createdBy");
    if (!room) return res.status(404).json({ message: "Sala no encontrada" });
    res.json(room);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener sala" });
  }
});

// Buscar sala por PIN
router.get("/pin/:pin", validatePin, async (req, res) => {
  try {
    const room = await Room.findOne({ pin: req.params.pin }).populate("createdBy");
    if (!room) return res.status(404).json({ message: "Sala no encontrada con ese PIN" });
    res.json(room);
  } catch (err) {
    res.status(500).json({ message: "Error al buscar sala por PIN" });
  }
});

export default router;
