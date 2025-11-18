import { detectSteganography } from '../utils/steganographyDetector.js';
import fs from 'fs';
import { errorLog } from '../utils/logger.js';

export const diagnoseFile = async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'No file uploaded' });

    const analysis = await detectSteganography(file.path);

    // limpiar archivo temporal
    try { fs.unlinkSync(file.path); } catch (e) {}

    return res.json({ analysis });
  } catch (err) {
    errorLog('Error diagnosing file', err);
    return res.status(500).json({ message: 'Error diagnosing file', error: err.message });
  }
};
