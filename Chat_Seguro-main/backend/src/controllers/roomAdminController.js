import Room from "../models/Room.js";
import UserRoom from "../models/UserRoom.js";

// 🔹 Obtener salas creadas por el usuario (admin)
export const getAdminRooms = async (req, res) => {
  try {
    const userId = req.user._id;
    const rooms = await Room.find({ createdBy: userId });
    res.json(rooms);
  } catch (err) {
    res.status(500).json({ message: "Error al obtener salas del admin", error: err.message });
  }
};

// 🔹 Editar una sala
export const updateRoom = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type } = req.body;

    const room = await Room.findById(id);
    if (!room) return res.status(404).json({ message: "Sala no encontrada" });

    // Solo el creador puede editar
    if (room.createdBy.toString() !== req.user._id.toString())
      return res.status(403).json({ message: "No autorizado" });

    room.name = name || room.name;
    room.type = type || room.type;
    await room.save();

    res.json({ message: "Sala actualizada correctamente", room });
  } catch (err) {
    res.status(500).json({ message: "Error al actualizar sala", error: err.message });
  }
};

// 🔹 Eliminar una sala
export const deleteRoom = async (req, res) => {
  try {
    const { id } = req.params;
    const room = await Room.findById(id);
    if (!room) return res.status(404).json({ message: "Sala no encontrada" });

    if (room.createdBy.toString() !== req.user._id.toString())
      return res.status(403).json({ message: "No autorizado" });

    // Eliminar inscripciones también
    await UserRoom.deleteMany({ room: room._id });
    await room.deleteOne();

    res.json({ message: "Sala eliminada correctamente" });
  } catch (err) {
    res.status(500).json({ message: "Error al eliminar sala", error: err.message });
  }
};
