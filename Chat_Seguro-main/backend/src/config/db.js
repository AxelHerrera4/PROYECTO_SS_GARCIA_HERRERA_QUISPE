import mongoose from "mongoose";
import { systemLog, errorLog } from "../utils/logger.js";

export const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    systemLog("✅", "Conectado a MongoDB");
  } catch (error) {
    errorLog("Error al conectar a MongoDB", error);
    process.exit(1);
  }
};
