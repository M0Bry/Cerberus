/**
 * Logger — Client-side logging.
 */
const isDev = import.meta.env.DEV;

export const logger = {
  info: (...args: any[]) => isDev && console.log("[INFO]", ...args),
  warn: (...args: any[]) => console.warn("[WARN]", ...args),
  error: (...args: any[]) => console.error("[ERROR]", ...args),
  debug: (...args: any[]) => isDev && console.debug("[DEBUG]", ...args),
};
