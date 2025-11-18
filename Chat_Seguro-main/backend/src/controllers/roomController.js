import Room from "../models/Room.js";
import crypto from "crypto";

// 🔹 Crear nueva sala
export const createRoom = async (req, res) => {
  try {
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
      createdBy: req.user?._id || null, // Guarda quién la creó
    });

    res.status(201).json({ message: "Sala creada correctamente", room });
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
