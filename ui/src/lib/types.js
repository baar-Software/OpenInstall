// JSDoc typedefs mirroring the frozen Â§7 backend contract (camelCase JSON keys).
// These are documentation-only; no runtime exports.

/**
 * Returned by the `resolve_oip` Tauri command. Side-effect-free result the
 * consent dialog renders. `trust` is the bare TrustLevel variant name.
 *
 * @typedef {Object} ResolveResult
 * @property {string} id
 * @property {string} name
 * @property {string} publisher
 * @property {string} version
 * @property {string} homepage
 * @property {string} sourceUrl
 * @property {"Verified" | "VerifiedNewPublisher" | "PublisherChanged" | "Unverified"} trust
 * @property {string} keyFingerprint
 * @property {number} payloadSize
 * @property {string} installToken
 */

/**
 * Returned by the `confirm_install` Tauri command.
 *
 * @typedef {Object} InstallResult
 * @property {boolean} success
 * @property {number | null} exitCode
 * @property {string} message
 */

export {};
