import Message from "../models/Message.js";
import { errorLog } from "../utils/logger.js";
import Room from "../models/Room.js";
import User from "../models/User.js";
import UserRoom from "../models/UserRoom.js";
import { encrypt, decrypt } from "../utils/encryption.js";
import { sanitizeString } from "../utils/sanitizer.js";

// Obtener mensajes de una sala con control de roles
export const getRoomMessages = async (req, res) => {
  try {
    const { roomId } = req.params;
    const messages = await Message.find({ room: roomId }).sort({ timestamp: 1 });

    // Si el requester es admin (no tiene 'username' en el objeto), devolver mensajes sin contenido
    const isAdmin = !req.user || !req.user.username;

    if (isAdmin) {
      const redacted = messages.map((msg) => ({
        _id: msg._id,
        room: msg.room,
        sender: decrypt(msg.sender),
        type: msg.type,
        fileUrl: msg.fileUrl,
        edited: msg.edited,
        timestamp: msg.timestamp,
      }));

      // Obtener participantes (nicknames) para la sala
      const participantsDocs = await UserRoom.find({ room: roomId }).select("nickname -_id");
      const participants = participantsDocs.map((p) => p.nickname);

      return res.json({ messages: redacted, participants });
    }

    // Usuario normal: devolver mensajes desencriptados completos (mantener formato anterior: array)
    const decryptedMessages = Message.decryptMessages(messages);
    return res.json(decryptedMessages);
  } catch (err) {
    errorLog("Error obteniendo mensajes", err, { roomId: req.params.roomId });
    res.status(500).json({ message: "Error al obtener mensajes" });
  }
};


// 🔹 Eliminar mensaje (solo admin o autor)
export const deleteMessage = async (req, res) => {
  try {
    const { id } = req.params; // id del mensaje
    const userId = req.user?._id;

    if (!userId)
      return res.status(401).json({ message: "Usuario no autenticado" });

    // Buscar mensaje y su sala
    const message = await Message.findById(id);
    if (!message)
      return res.status(404).json({ message: "Mensaje no encontrado" });

    const room = await Room.findById(message.room);
    const user = await User.findById(userId);

    if (!room || !user)
      return res.status(404).json({ message: "Sala o usuario no encontrado" });

    // Desencriptar sender para comparar
    const decryptedSender = decrypt(message.sender);

    // Validar si es admin o autor
    const isAdmin = room.createdBy?.toString() === userId.toString();
    const isAuthor = decryptedSender === user.username;

    if (!isAdmin && !isAuthor)
      return res.status(403).json({ message: "No autorizado" });

    // Marcar mensaje como eliminado (sin encriptar este mensaje del sistema)
    message.content = isAdmin
      ? "🗑️ Mensaje eliminado por el administrador"
      : "🗑️ Mensaje eliminado";
    message.type = "deleted";
    
    // Guardar sin pasar por el middleware de encriptación
    await Message.updateOne({ _id: id }, { 
      content: message.content, 
      type: "deleted" 
    });

    const updated = await Message.findById(id);
    const decrypted = updated.decryptMessage();

    res.json({ message: "Mensaje eliminado correctamente", updated: decrypted });
  } catch (err) {
    errorLog("Error al eliminar mensaje", err, { messageId: id });
    res.status(500).json({ message: "Error al eliminar mensaje", error: err.message });
  }
};

// 🔹 Editar mensaje (solo autor)
export const editMessage = async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user?._id;

    if (!userId)
      return res.status(401).json({ message: "Usuario no autenticado" });

    const safeContent = sanitizeString(content || '');
    if (!safeContent || !safeContent.trim())
      return res.status(400).json({ message: "El contenido no puede estar vacío" });

    // Buscar mensaje
    const message = await Message.findById(id);
    if (!message)
      return res.status(404).json({ message: "Mensaje no encontrado" });

    // Solo archivos no se pueden editar
    if (message.type === "file")
      return res.status(400).json({ message: "No puedes editar archivos" });

    const user = await User.findById(userId);
    if (!user)
      return res.status(404).json({ message: "Usuario no encontrado" });

    // Desencriptar sender para comparar
    const decryptedSender = decrypt(message.sender);

    // Solo el autor puede editar
    if (decryptedSender !== user.username)
      return res.status(403).json({ message: "Solo puedes editar tus propios mensajes" });

    // Actualizar mensaje (se encriptará automáticamente)
    message.content = safeContent.trim();
    message.edited = true;
    await message.save();

    // Desencriptar para respuesta
    const decrypted = message.decryptMessage();

    res.json({ message: "Mensaje editado correctamente", updated: decrypted });
  } catch (err) {
    errorLog("Error al editar mensaje", err, { messageId: id });
    res.status(500).json({ message: "Error al editar mensaje", error: err.message });
  }
};
