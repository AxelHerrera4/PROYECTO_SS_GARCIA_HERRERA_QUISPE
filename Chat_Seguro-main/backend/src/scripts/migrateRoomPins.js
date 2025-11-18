// Script de migración: Convierte PINs en claro a pinHash
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Cargar variables de entorno desde el directorio raíz
dotenv.config({ path: join(__dirname, "../../.env") });

// Conectar a MongoDB
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB conectado: ${conn.connection.host}`);
  } catch (error) {
    console.error("❌ Error conectando a MongoDB:", error.message);
    process.exit(1);
  }
};

const migrateRooms = async () => {
  try {
    await connectDB();

    // Obtener todas las salas
    const Room = mongoose.model("Room", new mongoose.Schema({
      name: String,
      pin: String,
      pinHash: String,
      type: String,
      createdBy: mongoose.Schema.Types.ObjectId,
      createdAt: Date
    }));

    const rooms = await Room.find({});
    console.log(`\n📊 Total de salas encontradas: ${rooms.length}`);

    let migrated = 0;
    let skipped = 0;
    let errors = 0;

    for (const room of rooms) {
      // Si ya tiene pinHash, skip
      if (room.pinHash) {
        console.log(`⏭️  Sala "${room.name}" ya tiene pinHash, omitiendo...`);
        skipped++;
        continue;
      }

      // Si tiene pin en claro, migrar
      if (room.pin) {
        try {
          const pinHash = await bcrypt.hash(room.pin, 10);
          room.pinHash = pinHash;
          room.pin = undefined; // Eliminar el campo pin
          await room.save();
          console.log(`✅ Sala "${room.name}" migrada (PIN hasheado)`);
          migrated++;
        } catch (err) {
          console.error(`❌ Error migrando sala "${room.name}":`, err.message);
          errors++;
        }
      } else {
        // No tiene ni pin ni pinHash → eliminar o generar uno nuevo
        console.log(`⚠️  Sala "${room.name}" no tiene PIN, eliminando...`);
        await room.deleteOne();
        errors++;
      }
    }

    console.log(`\n📈 Resumen de migración:`);
    console.log(`   ✅ Migradas: ${migrated}`);
    console.log(`   ⏭️  Omitidas: ${skipped}`);
    console.log(`   ❌ Errores: ${errors}`);
    console.log(`\n✨ Migración completada\n`);

    process.exit(0);
  } catch (error) {
    console.error("❌ Error en migración:", error);
    process.exit(1);
  }
};

migrateRooms();
