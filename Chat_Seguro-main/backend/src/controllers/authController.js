import jwt from "jsonwebtoken";
import User from "../models/User.js";
import Admin from "../models/Admin.js";
import validator from "validator";
import speakeasy from "speakeasy";
import QRCode from "qrcode";

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// Admin tokens (allows customizing payload)
const generateAdminToken = (id, opts = {}) => {
  const payload = { id };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: opts.expiresIn || "7d" });
};

// 🔐 Login de Usuario (solo nickname - sin registro previo)
export const loginUser = async (req, res) => {
  try {
    let { nickname } = req.body;

    // Sanitizar entrada
    nickname = validator.escape(nickname.trim());

    if (!nickname || nickname === "") {
      return res.status(400).json({ message: "El nickname es requerido" });
    }

    // Buscar o crear usuario temporal con ese nickname
    let user = await User.findOne({ username: nickname });

    if (!user) {
      // Crear usuario temporal automáticamente
      user = await User.create({
        name: nickname,
        username: nickname,
        email: `${nickname}@temp.chatapp.com`, // Email temporal
        password: Math.random().toString(36), // Password aleatorio (no se usará)
      });
    }

    res.json({
      _id: user._id,
      name: user.name,
      username: user.username,
      token: generateToken(user._id),
    });
  } catch (err) {
    res.status(500).json({ message: "Error al iniciar sesión", error: err.message });
  }
};

// 🔐 Login de Admin (solo el admin predefinido: admin/admin)
export const loginAdmin = async (req, res) => {
  try {
    let { username, password } = req.body;

    // Sanitizar entrada
    username = validator.escape(username.trim());

    // Solo permitir login con "admin"
    if (username !== "admin") {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const admin = await Admin.findOne({ email: "admin@chatapp.com" });

    if (!admin) {
      return res.status(500).json({ message: "Admin no encontrado. Contacte al administrador del sistema." });
    }

    if (await admin.matchPassword(password)) {
      // If admin has 2FA enabled, return a short-lived temporary token and indicate 2FA required
      if (admin.totpEnabled && admin.totpSecret) {
        const tempToken = jwt.sign({ id: admin._id, twoFactor: true }, process.env.JWT_SECRET, { expiresIn: "5m" });
        return res.json({ requires2fa: true, tempToken });
      }

      // No 2FA: issue full admin token
      res.json({
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        token: generateAdminToken(admin._id),
      });
    } else {
      res.status(401).json({ message: "Credenciales inválidas" });
    }
  } catch (err) {
    res.status(500).json({ message: "Error al iniciar sesión de admin", error: err.message });
  }
};

// Verify admin 2FA: accepts { code, tempToken }
export const verifyAdmin2FA = async (req, res) => {
  try {
    const { code } = req.body;
    let token = req.headers.authorization && req.headers.authorization.startsWith("Bearer")
      ? req.headers.authorization.split(" ")[1]
      : req.body.tempToken;

    if (!token) return res.status(400).json({ message: "Token temporal 2FA es requerido" });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Token temporal inválido o expirado" });
    }

    if (!decoded.twoFactor) return res.status(400).json({ message: "Token no es de verificación 2FA" });

    const admin = await Admin.findById(decoded.id);
    if (!admin || !admin.totpSecret) return res.status(400).json({ message: "Admin no tiene 2FA configurado" });

    const verified = speakeasy.totp.verify({
      secret: admin.totpSecret,
      encoding: 'base32',
      token: String(code),
      window: 1
    });

    if (!verified) return res.status(401).json({ message: "Código 2FA inválido" });

    // Issue full admin token
    const tokenFull = generateAdminToken(admin._id);
    res.json({ token: tokenFull, _id: admin._id, name: admin.name, email: admin.email });
  } catch (err) {
    res.status(500).json({ message: "Error al verificar 2FA", error: err.message });
  }
};

// Setup 2FA: generate secret and QR code. Protected route (admin must be authenticated)
export const setupAdmin2FA = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user._id);
    if (!admin) return res.status(404).json({ message: "Admin no encontrado" });

    const secret = speakeasy.generateSecret({ length: 20, name: `ChatApp (${admin.email})` });

    // Save temp secret until confirmed
    admin.totpTempSecret = secret.base32;
    await admin.save();

    // Return otpauth_url and a QR code data URL
    const otpauth = secret.otpauth_url;
    const qrDataUrl = await QRCode.toDataURL(otpauth);

    res.json({ otpauth, qrDataUrl });
  } catch (err) {
    res.status(500).json({ message: "Error generando 2FA", error: err.message });
  }
};

// Confirm 2FA setup: verify code against temp secret and enable
export const confirmAdmin2FA = async (req, res) => {
  try {
    const { code } = req.body;
    const admin = await Admin.findById(req.user._id);
    if (!admin || !admin.totpTempSecret) return res.status(400).json({ message: "No hay configuración 2FA en progreso" });

    const verified = speakeasy.totp.verify({
      secret: admin.totpTempSecret,
      encoding: 'base32',
      token: String(code),
      window: 1
    });

    if (!verified) return res.status(401).json({ message: "Código 2FA inválido" });

    // Promote temp secret to active
    admin.totpSecret = admin.totpTempSecret;
    admin.totpTempSecret = null;
    admin.totpEnabled = true;
    await admin.save();

    res.json({ message: "2FA habilitado" });
  } catch (err) {
    res.status(500).json({ message: "Error confirmando 2FA", error: err.message });
  }
};

// Disable 2FA: verify admin password and current TOTP code
export const disableAdmin2FA = async (req, res) => {
  try {
    const { password, code } = req.body;
    const admin = await Admin.findById(req.user._id);
    if (!admin) return res.status(404).json({ message: "Admin no encontrado" });

    if (!(await admin.matchPassword(password))) return res.status(401).json({ message: "Contraseña incorrecta" });

    if (admin.totpEnabled && admin.totpSecret) {
      const verified = speakeasy.totp.verify({ secret: admin.totpSecret, encoding: 'base32', token: String(code), window: 1 });
      if (!verified) return res.status(401).json({ message: "Código 2FA inválido" });
    }

    admin.totpSecret = null;
    admin.totpEnabled = false;
    admin.totpTempSecret = null;
    await admin.save();

    res.json({ message: "2FA deshabilitado" });
  } catch (err) {
    res.status(500).json({ message: "Error deshabilitando 2FA", error: err.message });
  }
};

// Obtener perfil del admin (sin password) - para frontend
export const getAdminProfile = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user._id).select('-password -totpSecret -totpTempSecret');
    if (!admin) return res.status(404).json({ message: 'Admin no encontrado' });
    res.json(admin);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo perfil', error: err.message });
  }
};

// ❌ Registro deshabilitado - ya no se permite registro manual
export const registerUser = async (req, res) => {
  res.status(403).json({ 
    message: "El registro manual está deshabilitado. Usa tu nickname para entrar directamente." 
  });
};
