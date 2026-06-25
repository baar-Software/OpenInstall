// Pure, testable gating logic for the consent dialog.
//
// This module decides only whether the Install button may be clickable. It can
// never enable a silent path: there is no auto-install, and clicking Install is
// always a separate explicit user action handled by the dialog.

export const TRUST_LEVELS = Object.freeze([
  "Verified",
  "VerifiedNewPublisher",
  "PublisherChanged",
  "Unverified",
]);

export function trustRequiresOverride(trust) {
  return trust === "PublisherChanged";
}

export function requiresOverride({ trust }) {
  return trustRequiresOverride(trust);
}

export function canInstall({ trust, overridden = false }) {
  const unknownTrust = !TRUST_LEVELS.includes(/** @type {any} */ (trust));
  if (unknownTrust) {
    return overridden === true;
  }
  if (requiresOverride({ trust })) {
    return overridden === true;
  }
  return true;
}
