import mongoose from "mongoose";

const blockedUploadSchema = new mongoose.Schema({
  originalName: { type: String },
  storedFilename: { type: String },
  mimetype: { type: String },
  reason: { type: String },
  detectedType: { type: String },
  entropy: { type: Number },
  hiddenFiles: { type: Array },
  room: { type: mongoose.Schema.Types.ObjectId, ref: "Room" },
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("BlockedUpload", blockedUploadSchema);
