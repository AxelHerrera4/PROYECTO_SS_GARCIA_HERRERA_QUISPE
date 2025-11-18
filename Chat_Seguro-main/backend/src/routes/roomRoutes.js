// routes/roomRoutes.js
import express from "express";
import Room from "../models/Room.js";
import { protectAny } from "../middleware/authMiddleware.js";
import { 
  validateCreateRoom, 
  validatePin 
} from "../middleware/validators.js";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const router = express.Router();

// Crear nueva sala (almacena hash del PIN)
router.post("/", protectAny, validateCreateRoom, async (req, res) => {
  try {
    console.log("🔵 POST /api/rooms - Body recibido:", req.body);
    const { name, type, pin } = req.body;

    // Generar PIN si no se proporcionó
    let roomPin = pin && pin.trim() !== "" ? pin : crypto.randomInt(1000, 9999).toString();

    // Si el usuario proporcionó un PIN específico, verificar que no exista
    if (pin && pin.trim() !== "") {
      const allRooms = await Room.find({}, { pinHash: 1, pin: 1 }).lean();
      
      for (const r of allRooms) {
        // Verificar contra pinHash
        if (r.pinHash && (await bcrypt.compare(roomPin, r.pinHash))) {
          return res.status(400).json({ message: "Ya existe una sala con ese PIN" });
        }
        // Fallback para salas legacy con pin en claro
        if (!r.pinHash && r.pin && r.pin === roomPin) {
          return res.status(400).json({ message: "Ya existe una sala con ese PIN" });
        }
      }
    }
    // Si el PIN fue generado aleatoriamente, no verificar (probabilidad de colisión es 0.01%)
    // En el caso extremadamente raro de colisión, el usuario puede crear otra sala

    const saltRounds = 10;
    const pinHash = await bcrypt.hash(roomPin, saltRounds);

    const room = await Room.create({
      name,
      type,
      pinHash,
      createdBy: req.user._id,
    });

    // Devolver el PIN generado/proporcionado al creador (NO lo almacenamos en claro)
    res.status(201).json({ message: "Sala creada correctamente", room, pin: roomPin });
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

// Buscar sala por PIN (comparando con hashes)
router.get("/pin/:pin", validatePin, async (req, res) => {
  try {
    const providedPin = req.params.pin;
    const rooms = await Room.find().populate("createdBy");
    for (const room of rooms) {
      if (room.pinHash && (await bcrypt.compare(providedPin, room.pinHash))) {
        return res.json(room);
      }
    }
    return res.status(404).json({ message: "Sala no encontrada con ese PIN" });
  } catch (err) {
    res.status(500).json({ message: "Error al buscar sala por PIN" });
  }
});

export default router;
