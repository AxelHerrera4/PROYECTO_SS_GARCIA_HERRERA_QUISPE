import mongoose from "mongoose";

const userRoomSchema = new mongoose.Schema({
  nickname: { type: String, required: true },
  room: { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true },
  joinedAt: { type: Date, default: Date.now },
});

export default mongoose.model("UserRoom", userRoomSchema);
