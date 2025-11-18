// logger.js - Sistema de logging seguro sin datos sensibles

// Configuración: cambiar a true para debugging (mostrará datos sensibles)
const ENABLE_SENSITIVE_LOGS = false;

/**
 * Logger seguro que oculta datos sensibles en producción
 * @param {string} emoji - Emoji para el log
 * @param {string} action - Descripción de la acción
 * @param {object} data - Datos a loggear
 */
export const secureLog = (emoji, action, data = {}) => {
  if (!ENABLE_SENSITIVE_LOGS) {
    // Modo seguro: ocultar datos sensibles
    const safeData = {};
    
    // Solo incluir datos no sensibles
    if (data.roomId) safeData.roomId = data.roomId;
    if (data.socketId) safeData.socketId = data.socketId;
    if (data.type) safeData.type = data.type;
    if (data.mimetype) safeData.mimetype = data.mimetype;
    if (data.messageId) safeData.messageId = data.messageId;
    if (data.timestamp) safeData.timestamp = data.timestamp;
    if (data.cooldownMs) safeData.cooldownMs = data.cooldownMs;
    if (data.inactiveTime) safeData.inactiveTime = data.inactiveTime;
    
    // Marcar datos sensibles como ocultos
    if (data.nickname) safeData.nickname = "[OCULTO]";
    if (data.sender) safeData.sender = "[OCULTO]";
    if (data.content) safeData.content = "[ENCRIPTADO]";
    if (data.message) safeData.message = "[OCULTO]";
    if (data.targetNickname) safeData.targetNickname = "[OCULTO]";
    if (data.adminNickname) safeData.adminNickname = "[OCULTO]";
    if (data.fileName) safeData.fileName = "[OCULTO]";
    if (data.username) safeData.username = "[OCULTO]";
    
    const dataStr = Object.keys(safeData).length > 0 ? JSON.stringify(safeData) : '';
    console.log(`${emoji} ${action} ${dataStr}`);
  } else {
    // Modo debugging: mostrar todo (solo para desarrollo)
    console.log(`${emoji} ${action}`, data);
  }
};

/**
 * Log de error (siempre se muestra, pero sin datos sensibles)
 */
export const errorLog = (action, error, context = {}) => {
  const safeContext = {};
  if (context.roomId) safeContext.roomId = context.roomId;
  if (context.socketId) safeContext.socketId = context.socketId;
  if (context.messageId) safeContext.messageId = context.messageId;
  
  console.error(`❌ ${action}`, {
    error: error.message || error,
    ...safeContext
  });
};

/**
 * Log de sistema (siempre se muestra)
 */
export const systemLog = (emoji, message) => {
  console.log(`${emoji} ${message}`);
};
