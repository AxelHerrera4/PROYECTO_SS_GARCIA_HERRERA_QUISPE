import Admin from "../models/Admin.js";
import { systemLog, errorLog } from "../utils/logger.js";

/**
 * Inicializa el admin predefinido en la base de datos
 * Usuario: admin
 * Password: admin
 */
export const initializeAdmin = async () => {
  try {
    // Verificar si ya existe el admin
    const adminExists = await Admin.findOne({ email: "admin@chatapp.com" });

    if (!adminExists) {
      // Crear admin (el modelo se encarga del hasheo automáticamente)
      await Admin.create({
        name: "Administrador",
        email: "admin@chatapp.com",
        password: "admin", // El pre-save hook se encargará del hasheo
      });
      systemLog("✅", "Admin predeterminado creado: admin/admin");
    } else {
      systemLog("ℹ️", "Admin predeterminado ya existe");
    }
  } catch (error) {
    errorLog("Error al inicializar admin", error);
  }
};
