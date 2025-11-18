import mongoose from "mongoose";
import { encrypt, decrypt } from "../utils/encryption.js";

const messageSchema = new mongoose.Schema({
  room: { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true },
  sender: { type: String, required: true }, // Se encriptará antes de guardar
  content: { type: String, required: true }, // Se encriptará antes de guardar
  type: { type: String, default: "text" }, // "text", "file", "deleted"
  fileUrl: { type: String }, // URL del archivo si es tipo file
  edited: { type: Boolean, default: false }, // Indica si el mensaje fue editado
  timestamp: { type: Date, default: Date.now },
});

// 🔐 Middleware: Encriptar antes de guardar
messageSchema.pre("save", function (next) {
  try {
    // Encriptar el contenido del mensaje
    if (this.isModified("content") && this.content) {
      this.content = encrypt(this.content);
    }

    // Encriptar el nombre del remitente
    if (this.isModified("sender") && this.sender) {
      this.sender = encrypt(this.sender);
    }

    next();
  } catch (error) {
    console.error("❌ Error al encriptar mensaje:", error);
    next(error);
  }
});

// 🔓 Método: Desencriptar mensaje
messageSchema.methods.decryptMessage = function () {
  return {
    _id: this._id,
    room: this.room,
    sender: decrypt(this.sender),
    content: decrypt(this.content),
    type: this.type,
    fileUrl: this.fileUrl,
    edited: this.edited,
    timestamp: this.timestamp,
  };
};

// 🔓 Método estático: Desencriptar array de mensajes
messageSchema.statics.decryptMessages = function (messages) {
  return messages.map((msg) => {
    if (msg.decryptMessage) {
      return msg.decryptMessage();
    }
    // Si es un objeto plano
    return {
      _id: msg._id,
      room: msg.room,
      sender: decrypt(msg.sender),
      content: decrypt(msg.content),
      type: msg.type,
      fileUrl: msg.fileUrl,
      edited: msg.edited,
      timestamp: msg.timestamp,
    };
  });
};

// ✅ Índice para búsquedas rápidas por sala y tiempo
messageSchema.index({ room: 1, timestamp: 1 });

export default mongoose.model("Message", messageSchema);
