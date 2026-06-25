/** Human-readable byte size. */
export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return String(bytes);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Format a unix-seconds string/number as a local date, or "" if invalid. */
export function formatUnixSeconds(s) {
  const n = Number(s);
  if (!Number.isFinite(n) || n <= 0) return "";
  try {
    return new Date(n * 1000).toLocaleDateString();
  } catch {
    return "";
  }
}
