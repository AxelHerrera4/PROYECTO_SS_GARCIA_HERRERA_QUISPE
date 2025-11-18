import User from "../models/User.js";
import Room from "../models/Room.js";
import UserRoom from "../models/UserRoom.js";

// 🔹 Obtener salas donde está unido el usuario
export const getUserRooms = async (req, res) => {
  try {
    const { nickname } = req.params;
    const userRooms = await UserRoom.find({ nickname }).populate("room");
    res.json(userRooms.map((ur) => ur.room));
  } catch (err) {
    res.status(500).json({ message: "Error al obtener salas", error: err });
  }
};

// 🔹 Unirse a una sala
export const joinRoom = async (req, res) => {
  try {
    const { nickname, pin } = req.body;
    const room = await Room.findOne({ pin });
    if (!room) return res.status(404).json({ message: "PIN inválido" });

    const exists = await UserRoom.findOne({ nickname, room: room._id });
    if (exists)
      return res.json({ roomId: room._id, roomName: room.name, joined: true });

    await UserRoom.create({ nickname, room: room._id });
    res.json({ roomId: room._id, roomName: room.name });
  } catch (err) {
    res.status(500).json({ message: "Error al unirse a la sala", error: err });
  }
};

// 🔹 Obtener salas creadas por el usuario
export const getCreatedRooms = async (req, res) => {
  try {
    const { nickname } = req.params;
    const user = await User.findOne({ username: nickname });

    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

    const rooms = await Room.find({ createdBy: user._id });
    res.json(rooms);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener tus salas creadas", error: err.message });
  }
};

// 🔹 Obtener detalles de una sala
export const getRoomDetails = async (req, res) => {
  try {
    const { roomId } = req.params;
    const room = await Room.findById(roomId);
    if (!room) return res.status(404).json({ message: "Sala no encontrada" });
    res.json(room);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener detalles de la sala", error: err });
  }
};