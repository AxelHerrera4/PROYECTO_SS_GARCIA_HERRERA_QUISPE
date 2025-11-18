import Admin from "../models/Admin.js";
import Room from "../models/Room.js";
import jwt from "jsonwebtoken";
import { secureLog, errorLog } from "../utils/logger.js";

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secretkey", {
    expiresIn: "7d",
  });
};

// 🔹 Registro
export const registerAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exists = await Admin.findOne({ email });
    if (exists) return res.status(400).json({ message: "Admin ya existe" });

    const admin = await Admin.create({ name, email, password });

    res.status(201).json({
      _id: admin._id,
      name: admin.name,
      email: admin.email,
      token: generateToken(admin._id),
    });
  } catch (err) {
    res.status(500).json({ message: "Error al registrar admin", error: err });
  }
};

// 🔹 Login
export const loginAdmin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (admin && (await admin.matchPassword(password))) {
      res.json({
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        token: generateToken(admin._id),
      });
    } else {
      res.status(401).json({ message: "Credenciales inválidas" });
    }
  } catch (err) {
    res.status(500).json({ message: "Error al iniciar sesión", error: err });
  }
};

// 🔹 Obtener salas creadas por el usuario
export const getMyRooms = async (req, res) => {
  try {
    secureLog("🔍", "Obteniendo salas de admin", { userId: req.user._id.toString() });
    const rooms = await Room.find({ createdBy: req.user._id });
    secureLog("📋", "Salas encontradas", { count: rooms.length });
    res.json(rooms);
  } catch (err) {
    errorLog("Error al obtener salas", err);
    res.status(500).json({ message: "Error al obtener salas", error: err.message });
  }
};

// 🔹 Actualizar sala
export const updateRoom = async (req, res) => {
  try {
    const { name, type } = req.body;
    const room = await Room.findById(req.params.id);

    secureLog("🔍", "Editando sala", { roomId: req.params.id });

    if (!room) {
      return res.status(404).json({ message: "Sala no encontrada" });
    }

    // Verificar que el usuario sea el creador
    if (room.createdBy.toString() !== req.user._id.toString()) {
      secureLog("❌", "Usuario no autorizado para editar sala", { roomId: req.params.id });
      return res.status(403).json({ message: "No tienes permiso para editar esta sala" });
    }

    room.name = name || room.name;
    room.type = type || room.type;
    await room.save();

    secureLog("✅", "Sala actualizada", { roomId: req.params.id });
    res.json({ message: "Sala actualizada correctamente", room });
  } catch (err) {
    errorLog("Error al actualizar sala", err, { roomId: req.params.id });
    res.status(500).json({ message: "Error al actualizar sala", error: err.message });
  }
};

// 🔹 Eliminar sala
export const deleteRoom = async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);

    secureLog("🗑️", "Eliminando sala", { roomId: req.params.id });

    if (!room) {
      return res.status(404).json({ message: "Sala no encontrada" });
    }

    // Verificar que el usuario sea el creador
    if (room.createdBy.toString() !== req.user._id.toString()) {
      secureLog("❌", "Usuario no autorizado para eliminar sala", { roomId: req.params.id });
      return res.status(403).json({ message: "No tienes permiso para eliminar esta sala" });
    }

    await Room.findByIdAndDelete(req.params.id);
    secureLog("✅", "Sala eliminada", { roomId: req.params.id });
    res.json({ message: "Sala eliminada correctamente" });
  } catch (err) {
    errorLog("Error al eliminar sala", err, { roomId: req.params.id });
    res.status(500).json({ message: "Error al eliminar sala", error: err.message });
  }
};
