import DownloadLog from '../models/DownloadLog.js';
import { secureLog, errorLog } from '../utils/logger.js';

export const logDownload = async (req, res) => {
  try {
    const { originalName, storedFilename, url, mimetype, room, downloader } = req.body;
    const ip = req.ip || req.headers['x-forwarded-for'] || null;

    const entry = await DownloadLog.create({ originalName, storedFilename, url, mimetype, room, downloader, ip });
    secureLog('⬇️', 'Download logged', { originalName, storedFilename, room, downloader, ip });
    res.status(201).json({ message: 'Download logged', id: entry._id });
  } catch (error) {
    errorLog('Error logging download', error);
    res.status(500).json({ message: 'Error logging download' });
  }
};

export const getDownloads = async (req, res) => {
  try {
    // optional query params: room, limit, skip
    const { room, limit = 50, skip = 0 } = req.query;
    const q = {};
    if (room) q.room = room;

    const downloads = await DownloadLog.find(q).sort({ createdAt: -1 }).limit(Number(limit)).skip(Number(skip));
    res.json({ downloads });
  } catch (error) {
    errorLog('Error fetching download logs', error);
    res.status(500).json({ message: 'Error fetching download logs' });
  }
};
