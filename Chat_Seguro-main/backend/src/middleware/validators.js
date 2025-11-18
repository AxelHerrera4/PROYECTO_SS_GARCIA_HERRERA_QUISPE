import { body, param, validationResult } from "express-validator";
import validator from "validator";

// Middleware para manejar errores de validación
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log("❌ Errores de validación:", JSON.stringify(errors.array(), null, 2));
    return res.status(400).json({ 
      message: "Errores de validación", 
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }
  next();
};

// Validación para crear sala
export const validateCreateRoom = [
  body("name")
    .trim()
    .notEmpty()
    .withMessage("El nombre de la sala es requerido")
    .isLength({ min: 3, max: 50 })
    .withMessage("El nombre debe tener entre 3 y 50 caracteres")
    .matches(/^[a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ\-_]+$/)
    .withMessage("El nombre solo puede contener letras, números, espacios y guiones")
    .customSanitizer(value => validator.escape(value)),
  
  body("type")
    .trim()
    .notEmpty()
    .withMessage("El tipo de sala es requerido")
    .isIn(["texto", "multimedia", "standard"])
    .withMessage("El tipo debe ser 'texto', 'standard' o 'multimedia'"),
  
  body("pin")
    .optional()
    .trim()
    .isLength({ min: 4, max: 4 })
    .withMessage("El PIN debe tener exactamente 4 caracteres")
    .matches(/^[0-9]+$/)
    .withMessage("El PIN solo puede contener números"),
  
  handleValidationErrors
];

// Validación para actualizar sala
export const validateUpdateRoom = [
  body("name")
    .optional()
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage("El nombre debe tener entre 3 y 50 caracteres")
    .matches(/^[a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ\-_]+$/)
    .withMessage("El nombre solo puede contener letras, números, espacios y guiones")
    .customSanitizer(value => validator.escape(value)),
  
  body("type")
    .optional()
    .trim()
    .isIn(["texto", "multimedia", "standard"])
    .withMessage("El tipo debe ser 'texto', 'standard' o 'multimedia'"),
  
  handleValidationErrors
];

// Validación para login de usuario
export const validateUserLogin = [
  body("nickname")
    .trim()
    .notEmpty()
    .withMessage("El nickname es requerido")
    .isLength({ min: 2, max: 20 })
    .withMessage("El nickname debe tener entre 2 y 20 caracteres")
    .matches(/^[a-zA-Z0-9_\-]+$/)
    .withMessage("El nickname solo puede contener letras, números, guiones y guiones bajos")
    .customSanitizer(value => validator.escape(value)),
  
  handleValidationErrors
];

// Validación para login de admin
export const validateAdminLogin = [
  body("username")
    .trim()
    .notEmpty()
    .withMessage("El usuario es requerido")
    .isLength({ min: 3, max: 20 })
    .withMessage("El usuario debe tener entre 3 y 20 caracteres")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("El usuario solo puede contener letras, números y guiones bajos")
    .customSanitizer(value => validator.escape(value)),
  
  body("password")
    .notEmpty()
    .withMessage("La contraseña es requerida")
    .isLength({ min: 3, max: 50 })
    .withMessage("La contraseña debe tener entre 3 y 50 caracteres"),
  
  handleValidationErrors
];

// Validación para unirse a sala
export const validateJoinRoom = [
  body("nickname")
    .trim()
    .notEmpty()
    .withMessage("El nickname es requerido")
    .isLength({ min: 2, max: 20 })
    .withMessage("El nickname debe tener entre 2 y 20 caracteres")
    .matches(/^[a-zA-Z0-9_\-]+$/)
    .withMessage("El nickname solo puede contener letras, números, guiones y guiones bajos")
    .customSanitizer(value => validator.escape(value)),
  
  body("pin")
    .trim()
    .notEmpty()
    .withMessage("El PIN es requerido")
    .isLength({ min: 4, max: 4 })
    .withMessage("El PIN debe tener exactamente 4 caracteres")
    .matches(/^[0-9]+$/)
    .withMessage("El PIN solo puede contener números"),
  
  handleValidationErrors
];

// Validación para mensajes
export const validateMessage = [
  body("roomId")
    .trim()
    .notEmpty()
    .withMessage("El ID de la sala es requerido")
    .isMongoId()
    .withMessage("ID de sala inválido"),
  
  body("sender")
    .trim()
    .notEmpty()
    .withMessage("El remitente es requerido")
    .isLength({ min: 2, max: 20 })
    .withMessage("El remitente debe tener entre 2 y 20 caracteres")
    .customSanitizer(value => validator.escape(value)),
  
  body("content")
    .trim()
    .notEmpty()
    .withMessage("El contenido es requerido")
    .isLength({ max: 5000 })
    .withMessage("El mensaje no puede exceder 5000 caracteres")
    .customSanitizer(value => validator.escape(value)),
  
  body("type")
    .optional()
    .isIn(["text", "file", "image", "video", "audio"])
    .withMessage("Tipo de mensaje inválido"),
  
  handleValidationErrors
];

// Validación para IDs de MongoDB
export const validateMongoId = [
  param("id")
    .isMongoId()
    .withMessage("ID inválido"),
  
  handleValidationErrors
];

// Validación para PIN
export const validatePin = [
  param("pin")
    .trim()
    .isLength({ min: 4, max: 4 })
    .withMessage("El PIN debe tener exactamente 4 caracteres")
    .matches(/^[0-9]+$/)
    .withMessage("El PIN solo puede contener números"),
  
  handleValidationErrors
];
