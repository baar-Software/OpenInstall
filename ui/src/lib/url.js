// Small URL helpers for the consent dialog. Display-only; never used to decide
// trust (the backend already resolved + verified the host).

/**
 * Extract the host (authority) from a resolved https source URL for the
 * "<host> wants to install" header. Falls back to the raw string if it cannot
 * be parsed, so the dialog never shows an empty header.
 *
 * @param {string} sourceUrl - e.g. "https://dl.example.com/app.oip".
 * @returns {string}
 */
export function hostFromSourceUrl(sourceUrl) {
  if (!sourceUrl) return "";
  try {
    return new URL(sourceUrl).host;
  } catch {
    return sourceUrl;
  }
}

/**
 * Read a dev/manual fallback openinstall:// (or https) URL from the page query
 * string, e.g. `?url=openinstall://host/path`. Returns null if absent.
 *
 * @param {string} [search] - location.search; defaults to window.location.search.
 * @returns {string | null}
 */
export function urlFromQuery(search) {
  const qs =
    search ??
    (typeof window !== "undefined" && window.location
      ? window.location.search
      : "");
  if (!qs) return null;
  try {
    const value = new URLSearchParams(qs).get("url");
    return value && value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/**
 * Convert an OpenInstall repo-add link into a repo source URL.
 *
 * Supported forms:
 *   openinstall://repo?url=https%3A%2F%2Fexample.com%2Fopeninstall
 *   openinstall://repo/example.com/openinstall
 *
 * Returns null for ordinary app/package links.
 *
 * @param {string} value
 * @returns {string | null}
 */
export function repoSourceFromLink(value) {
  if (!value) return null;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== "openinstall:" || parsed.host !== "repo") return null;

  const fromQuery = parsed.searchParams.get("url");
  if (fromQuery) return fromQuery;

  const path = parsed.pathname.replace(/^\/+/, "");
  if (!path) return null;
  return `https://${path}`;
}
