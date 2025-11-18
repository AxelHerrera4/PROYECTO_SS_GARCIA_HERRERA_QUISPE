import fs from "fs";
import StreamZip from "node-stream-zip";
import Unrar from "node-unrar-js";

const MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024; // 200 MB
const MAX_FILES = 5000;
const MAX_RATIO = 50; // tamaño_descomprimido / tamaño_comprimido

export async function detectArchiveBomb(filePath, ext) {
  const stats = fs.statSync(filePath);
  const compressedSize = stats.size;

  // 📦 Manejo ZIP
  if (ext === ".zip") {
    const zip = new StreamZip.async({ file: filePath });
    try {
      const entries = await zip.entries();
      const files = Object.values(entries);
      const filesCount = files.length;

      let totalUncompressed = 0;

      for (const entry of files) {
        if (!entry.isDirectory) {
          totalUncompressed += entry.size;
          if (totalUncompressed > MAX_UNCOMPRESSED_BYTES) break;
        }
      }

      const ratio =
        compressedSize > 0 ? totalUncompressed / compressedSize : Infinity;

      const isBomb =
        filesCount > MAX_FILES ||
        totalUncompressed > MAX_UNCOMPRESSED_BYTES ||
        ratio > MAX_RATIO;

      return {
        isBomb,
        type: "zip",
        stats: {
          filesCount,
          totalUncompressed,
          compressedSize,
          ratio,
        },
      };
    } finally {
      await zip.close();
    }
  }

  // 📦 Manejo RAR
  if (ext === ".rar") {
    const data = fs.readFileSync(filePath);
    const extractor = Unrar.createExtractorFromData({ data });
    const list = extractor.getFileList();

    if (list[0].state !== "SUCCESS") {
      // Archivo RAR corrupto o ilegible = sospechoso
      return {
        isBomb: true,
        type: "rar",
        stats: { error: "RAR corrupto o ilegible" },
      };
    }

    const files = list[1].fileHeaders || [];
    const filesCount = files.length;
    let totalUncompressed = 0;

    for (const f of files) {
      totalUncompressed += f.uncompressedSize || 0;
      if (totalUncompressed > MAX_UNCOMPRESSED_BYTES) break;
    }

    const ratio =
      compressedSize > 0 ? totalUncompressed / compressedSize : Infinity;

    const isBomb =
      filesCount > MAX_FILES ||
      totalUncompressed > MAX_UNCOMPRESSED_BYTES ||
      ratio > MAX_RATIO;

    return {
      isBomb,
      type: "rar",
      stats: {
        filesCount,
        totalUncompressed,
        compressedSize,
        ratio,
      },
    };
  }

  // Si no es zip/rar
  return { isBomb: false, type: "other", stats: {} };
}
