import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import yauzl from 'yauzl';
import { config } from '../config/index.js';

/**
 * Resolves a ZIP entry name inside `destination`.
 * Returns null for entries that are absolute, contain traversal segments or
 * otherwise escape the destination directory (Zip Slip, CWE-22).
 */
export function safeEntryPath(destination, entryName) {
  if (typeof entryName !== 'string' || entryName === '') return null;
  const normalized = entryName.replace(/\\/g, '/');
  if (normalized.startsWith('/') || /^[a-zA-Z]:\//.test(normalized)) return null;
  if (normalized.split('/').some((segment) => segment === '..')) return null;
  const resolvedRoot = path.resolve(destination);
  const target = path.resolve(resolvedRoot, normalized);
  if (target !== resolvedRoot && !target.startsWith(resolvedRoot + path.sep)) return null;
  return target;
}

function isSymlink(entry) {
  // Upper 16 bits of externalFileAttributes hold the unix mode on POSIX zips.
  const mode = (entry.externalFileAttributes >>> 16) & 0xffff;
  return (mode & 0xf000) === 0xa000;
}

function openZip(zipPath) {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (error, zipfile) => {
      if (error) reject(error);
      else resolve(zipfile);
    });
  });
}

/**
 * Extracts a ZIP archive into `destination` with protection against Zip Slip,
 * symlink escapes and zip bombs.
 */
export async function extractZip(zipPath, destination, limits = {}) {
  const maxBytes = limits.maxBytes ?? config.maxExtractedBytes;
  const maxEntries = limits.maxEntries ?? config.maxExtractedEntries;
  await fsp.mkdir(destination, { recursive: true });
  const zipfile = await openZip(zipPath);
  let entries = 0;
  let bytes = 0;
  const skipped = [];

  await new Promise((resolve, reject) => {
    zipfile.on('error', reject);
    zipfile.on('end', resolve);
    zipfile.readEntry();

    zipfile.on('entry', (entry) => {
      (async () => {
        entries += 1;
        if (entries > maxEntries) throw new Error(`Archive contains more than ${maxEntries} entries`);
        const target = safeEntryPath(destination, entry.fileName);
        if (target === null || isSymlink(entry)) {
          skipped.push(entry.fileName);
          zipfile.readEntry();
          return;
        }
        if (entry.fileName.endsWith('/')) {
          await fsp.mkdir(target, { recursive: true });
          zipfile.readEntry();
          return;
        }
        bytes += entry.uncompressedSize;
        if (bytes > maxBytes) throw new Error(`Archive expands beyond the ${maxBytes} byte limit`);
        await fsp.mkdir(path.dirname(target), { recursive: true });
        const readStream = await new Promise((res, rej) => {
          zipfile.openReadStream(entry, (error, stream) => (error ? rej(error) : res(stream)));
        });
        await pipeline(readStream, fs.createWriteStream(target, { mode: 0o600 }));
        zipfile.readEntry();
      })().catch((error) => {
        zipfile.close();
        reject(error);
      });
    });
  });

  return { entries, bytes, skipped };
}

/**
 * If the archive contained a single top-level directory (the usual GitHub /
 * ADO export layout), returns that directory so models see the project root.
 */
export async function resolveSourceRoot(directory) {
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  const visible = entries.filter((entry) => !entry.name.startsWith('__MACOSX'));
  if (visible.length === 1 && visible[0].isDirectory()) {
    return path.join(directory, visible[0].name);
  }
  return directory;
}
