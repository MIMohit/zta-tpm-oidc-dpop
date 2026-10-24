import { fileURLToPath } from "node:url";
import path from "node:path";
import process from "node:process";

/**
 * Returns true if the calling module is the main process entry point.
 * @param {string} metaUrl - import.meta.url of the calling module
 * @returns {boolean}
 */
export function isMain(metaUrl) {
  if (!metaUrl || !process.argv[1]) return false;
  try {
    const scriptPath = path.resolve(process.argv[1]);
    const modulePath = path.resolve(fileURLToPath(metaUrl));
    return scriptPath === modulePath;
  } catch {
    return false;
  }
}

export default isMain;
