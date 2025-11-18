import express from "express";
import {
  getUserRooms,
  joinRoom,
  getCreatedRooms,   // 👈 asegúrate de tener esta importación
} from "../controllers/userController.js";
import { validateJoinRoom } from "../middleware/validators.js";

const router = express.Router();

router.get("/:nickname/rooms", getUserRooms);
router.get("/:nickname/created", getCreatedRooms); // ✅ Nueva ruta
router.post("/join", validateJoinRoom, joinRoom);

export default router;
