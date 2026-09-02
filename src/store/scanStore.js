import { EventEmitter } from 'node:events';

/**
 * In-memory scan store. Scans are transient by design: the persisted artefacts
 * are the source workspace and the generated report.
 */
export class ScanStore extends EventEmitter {
  #scans = new Map();

  create(scan) {
    this.#scans.set(scan.id, scan);
    this.emit('update', scan);
    return scan;
  }

  get(id) {
    return this.#scans.get(id) ?? null;
  }

  list() {
    return [...this.#scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  update(id, patch) {
    const scan = this.#scans.get(id);
    if (!scan) return null;
    Object.assign(scan, patch, { updatedAt: new Date().toISOString() });
    this.emit('update', scan);
    return scan;
  }

  updateModel(id, modelId, patch) {
    const scan = this.#scans.get(id);
    if (!scan) return null;
    const model = scan.models.find((entry) => entry.id === modelId);
    if (model) Object.assign(model, patch);
    scan.updatedAt = new Date().toISOString();
    this.emit('update', scan);
    return scan;
  }
}

export const scanStore = new ScanStore();
