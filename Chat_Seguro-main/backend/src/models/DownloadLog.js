import mongoose from 'mongoose';

const DownloadLogSchema = new mongoose.Schema({
  originalName: { type: String },
  storedFilename: { type: String },
  url: { type: String },
  mimetype: { type: String },
  downloader: { type: String }, // nickname or user id
  room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room' },
  ip: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const DownloadLog = mongoose.models.DownloadLog || mongoose.model('DownloadLog', DownloadLogSchema);
export default DownloadLog;
