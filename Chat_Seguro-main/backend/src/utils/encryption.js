import crypto from "crypto";

// Algoritmo de encriptación (AES-256-CBC)
const ALGORITHM = "aes-256-cbc";

// Clave de encriptación (debe estar en .env en producción)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");

// Asegurar que la clave tenga 32 bytes
const getKey = () => {
  const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), "hex");
  if (key.length !== 32) {
    throw new Error("La clave de encriptación debe tener 32 bytes (64 caracteres hex)");
  }
  return key;
};

/**
 * Encripta un texto usando AES-256-CBC
 * @param {string} text - Texto a encriptar
 * @returns {string} - Texto encriptado en formato "iv:encryptedData"
 */
export const encrypt = (text) => {
  if (!text) return text;

  try {
    // Generar un IV (Initialization Vector) aleatorio de 16 bytes
    const iv = crypto.randomBytes(16);

    // Crear el cipher
    const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);

    // Encriptar el texto
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Retornar IV + datos encriptados (separados por :)
    return `${iv.toString("hex")}:${encrypted}`;
  } catch (error) {
    console.error("❌ Error al encriptar:", error.message);
    return text; // En caso de error, retornar texto original
  }
};

/**
 * Desencripta un texto encriptado con AES-256-CBC
 * @param {string} encryptedText - Texto encriptado en formato "iv:encryptedData"
 * @returns {string} - Texto desencriptado
 */
export const decrypt = (encryptedText) => {
  if (!encryptedText) return encryptedText;

  try {
    // Separar IV y datos encriptados
    const parts = encryptedText.split(":");
    if (parts.length !== 2) {
      // Si no tiene el formato correcto, asumir que no está encriptado
      return encryptedText;
    }

    const iv = Buffer.from(parts[0], "hex");
    const encrypted = parts[1];

    // Crear el decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);

    // Desencriptar
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  } catch (error) {
    console.error("❌ Error al desencriptar:", error.message);
    return encryptedText; // En caso de error, retornar texto encriptado
  }
};

/**
 * Encripta un objeto completo (convierte a JSON, encripta, retorna)
 * @param {Object} obj - Objeto a encriptar
 * @returns {string} - JSON encriptado
 */
export const encryptObject = (obj) => {
  try {
    const jsonString = JSON.stringify(obj);
    return encrypt(jsonString);
  } catch (error) {
    console.error("❌ Error al encriptar objeto:", error.message);
    return obj;
  }
};

/**
 * Desencripta un objeto (desencripta, parsea JSON, retorna)
 * @param {string} encryptedString - String encriptado
 * @returns {Object} - Objeto desencriptado
 */
export const decryptObject = (encryptedString) => {
  try {
    const decryptedString = decrypt(encryptedString);
    return JSON.parse(decryptedString);
  } catch (error) {
    console.error("❌ Error al desencriptar objeto:", error.message);
    return encryptedString;
  }
};

/**
 * Genera una clave de encriptación aleatoria (para usar en .env)
 * @returns {string} - Clave de 32 bytes en hexadecimal
 */
export const generateEncryptionKey = () => {
  return crypto.randomBytes(32).toString("hex");
};

// Generar clave si no existe
if (!process.env.ENCRYPTION_KEY) {
  console.warn("⚠️ ENCRYPTION_KEY no está en .env. Generando una nueva clave...");
  console.log("📝 Agrega esto a tu .env:");
  console.log(`ENCRYPTION_KEY=${generateEncryptionKey()}`);
}
