import express from "express";
import { loginUser, loginAdmin, registerUser, verifyAdmin2FA, setupAdmin2FA, confirmAdmin2FA, disableAdmin2FA, getAdminProfile } from "../controllers/authController.js";
import { 
  validateUserLogin, 
  validateAdminLogin,
  handleValidationErrors
} from "../middleware/validators.js";
import { protectAdmin } from "../middleware/authMiddleware.js";
import { body } from "express-validator";

const router = express.Router();

// Login de usuario (solo nickname)
router.post("/login", validateUserLogin, loginUser);

// Login de admin (admin/admin)
router.post("/admin/login", validateAdminLogin, loginAdmin);

// Verify temporary 2FA token -> issue full token
router.post("/admin/verify-2fa", [ body("code").trim().isLength({ min: 4, max: 10 }).withMessage("Código 2FA inválido"), handleValidationErrors ], verifyAdmin2FA);

// 2FA setup (generate QR/secret) - protected route (must be fully authenticated)
router.post("/admin/2fa/setup", protectAdmin, setupAdmin2FA);

// Confirm setup (verify code and enable)
router.post("/admin/2fa/confirm", protectAdmin, [ body("code").trim().isLength({ min: 4, max: 10 }).withMessage("Código 2FA inválido"), handleValidationErrors ], confirmAdmin2FA);

// Disable 2FA (verify password + code)
router.post("/admin/2fa/disable", protectAdmin, [ body("password").notEmpty(), body("code").optional(), handleValidationErrors ], disableAdmin2FA);

// Obtener perfil admin (indica si 2FA está activado)
router.get("/admin/me", protectAdmin, getAdminProfile);

// Registro deshabilitado
router.post("/register", registerUser);

export default router;
