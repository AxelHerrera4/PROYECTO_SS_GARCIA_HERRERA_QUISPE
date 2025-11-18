import Room from "../models/Room.js";
import crypto from "crypto";
import bcrypt from "bcryptjs";

// 🔹 Crear nueva sala
export const createRoom = async (req, res) => {
  try {
    const { name, type, pin } = req.body;
    const roomPin = pin && pin.trim() !== "" ? pin : crypto.randomInt(1000, 9999).toString();

    // Solo verificar unicidad si el usuario proporcionó un PIN específico
    if (pin && pin.trim() !== "") {
      const allRooms = await Room.find({}, { pinHash: 1, pin: 1 }).lean();
      
      for (const r of allRooms) {
        if (r.pinHash && (await bcrypt.compare(roomPin, r.pinHash))) {
          return res.status(400).json({ message: "Ya existe una sala con ese PIN" });
        }
        if (!r.pinHash && r.pin && r.pin === roomPin) {
          return res.status(400).json({ message: "Ya existe una sala con ese PIN" });
        }
      }
    }
    // Si el PIN fue generado aleatoriamente, no verificar unicidad (muy baja probabilidad de colisión)

    const saltRounds = 10;
    const pinHash = await bcrypt.hash(roomPin, saltRounds);

    const room = await Room.create({
      name,
      type,
      pinHash,
      createdBy: req.user?._id || null, // Guarda quién la creó
    });

    // Devolver PIN al creador (no almacenado en claro)
    res.status(201).json({ message: "Sala creada correctamente", room, pin: roomPin });
  } catch (err) {
    console.error("Error al crear sala:", err);
    res.status(500).json({ message: "Error al crear sala", error: err.message });
  }
};

// 🔹 Obtener todas las salas
export const getAllRooms = async (req, res) => {
  try {
    const rooms = await Room.find().populate("createdBy", "username email");
    res.json(rooms);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error al obtener salas", error: err.message });
  }
};
