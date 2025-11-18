// Usar variable de entorno si está disponible, sino usar localhost
// Por defecto el backend corre en el puerto 4000 (ver backend/src/server.js)
export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";
