// models/Room.js
import mongoose from "mongoose";

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  // El PIN ya no se almacena en texto: guardamos su hash seguro (bcrypt)
  // Temporalmente opcional para permitir migración de salas legacy
  pinHash: { type: String, required: false },
  // Campo legacy (migrar a pinHash)
  pin: { type: String, required: false },
  type: { type: String, default: "standard" }, // 👈 "standard" o "multimedia"
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model("Room", roomSchema);
