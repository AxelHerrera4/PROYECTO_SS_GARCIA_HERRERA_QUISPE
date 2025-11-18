import mongoose from "mongoose";
import dotenv from "dotenv";
import Admin from "../models/Admin.js";

dotenv.config();

const resetAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/chatapp");
    console.log("📡 Conectado a MongoDB");

    // Eliminar admin existente
    const result = await Admin.deleteMany({ email: "admin@chatapp.com" });
    console.log(`🗑️ Eliminados ${result.deletedCount} admins`);

    // Crear nuevo admin con password correcta
    const newAdmin = await Admin.create({
      name: "Administrador",
      email: "admin@chatapp.com",
      password: "admin", // El pre-save hook hasheará esto
    });

    console.log("✅ Admin recreado correctamente:");
    console.log("   Usuario: admin");
    console.log("   Password: admin");
    console.log("   ID:", newAdmin._id);

    process.exit(0);
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
};

resetAdmin();
