import express from "express";
import { uploadFile } from "../controllers/fileController.js";
import { upload } from "../config/multer.js";
import { logDownload } from "../controllers/downloadController.js";
import { diagnoseFile } from "../controllers/diagnoseController.js";

const router = express.Router();

// POST /api/files/upload
router.post("/upload", upload.single("file"), uploadFile);

// POST /api/files/diagnose -> endpoint temporal para debug: analiza archivo y devuelve el objeto de diagnóstico
router.post('/diagnose', upload.single('file'), diagnoseFile);

// POST /api/files/downloaded -> registrar descarga (llamada desde frontend)
router.post('/downloaded', express.json(), logDownload);

export default router;
