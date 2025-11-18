import jwt from "jsonwebtoken";
import User from "../models/User.js";
import Admin from "../models/Admin.js";
import { errorLog } from "../utils/logger.js";

export const protect = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select("-password");
      next();
    } catch (err) {
      console.error("Error en middleware JWT:", err);
      res.status(401).json({ message: "Token inválido o expirado" });
    }
  } else {
    res.status(401).json({ message: "No autorizado, token no encontrado" });
  }
};

// Middleware específico para proteger rutas de admin
export const protectAdmin = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      // Reject temporary 2FA tokens (they have `twoFactor: true`) for protected admin routes
      if (decoded.twoFactor) {
        return res.status(401).json({ message: "Token temporal 2FA no autorizado para esta operación" });
      }

      req.user = await Admin.findById(decoded.id).select("-password");
      
      if (!req.user) {
        return res.status(401).json({ message: "Admin no encontrado" });
      }
      
      next();
    } catch (err) {
      console.error("Error en middleware JWT admin:", err);
      res.status(401).json({ message: "Token inválido o expirado" });
    }
  } else {
    res.status(401).json({ message: "No autorizado, token no encontrado" });
  }
};

// Middleware que funciona para User o Admin
export const protectAny = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Intentar buscar primero como User
      let user = await User.findById(decoded.id).select("-password");
      
      // Si no es User, intentar como Admin
      if (!user) {
        user = await Admin.findById(decoded.id).select("-password");
      }
      
      if (!user) {
        return res.status(401).json({ message: "Usuario no encontrado" });
      }
      
      req.user = user;
      next();
    } catch (err) {
      console.error("Error en middleware JWT:", err);
      res.status(401).json({ message: "Token inválido o expirado" });
    }
  } else {
    res.status(401).json({ message: "No autorizado, token no encontrado" });
  }
};

// Alias para tests
export const authMiddleware = protect;
