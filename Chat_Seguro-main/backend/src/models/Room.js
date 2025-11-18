// models/Room.js
import mongoose from "mongoose";

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  pin: { type: String, required: true, unique: true },
  type: { type: String, default: "standard" }, // 👈 "standard" o "multimedia"
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

export default mongoose.model("Room", roomSchema);
