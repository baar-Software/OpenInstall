// Thin wrappers around the Tauri command boundary and app commands.
// Keeping IPC in one place makes the frontend/backend contract explicit.
import { invoke } from "@tauri-apps/api/core";

// --- verify -> consent -> install (side-effect-free resolve; gated install) ---
export const resolveOip = (url) => invoke("resolve_oip", { url });
export const acknowledgeRisk = (installToken) =>
  invoke("acknowledge_risk", { installToken });
export const confirmInstall = (installToken) =>
  invoke("confirm_install", { installToken });

// --- settings / Developer Mode ---
export const getSettings = () => invoke("get_settings");
export const setDeveloperMode = (enabled) =>
  invoke("set_developer_mode", { enabled });

// --- launchpad ---
export const listInstalled = () => invoke("list_installed");
export const backfillIcons = () => invoke("backfill_icons");
export const launchApp = (id) => invoke("launch_app", { id });
// Fully uninstall: deletes the app's files, shortcut, and uninstall entry.
export const uninstallApp = (id) => invoke("uninstall_app", { id });

// --- OpenInstall repositories ---
export const listRepoSources = () => invoke("list_repo_sources");
export const addRepoSource = (url) => invoke("add_repo_source", { url });
export const removeRepoSource = (url) => invoke("remove_repo_source", { url });
export const fetchRepo = (url) => invoke("fetch_repo", { url });

// --- GUI package author ---
export const generateKeypair = (outPrefix, password) =>
  invoke("generate_keypair", { outPrefix, password });
export const buildPackage = (spec) => invoke("build_package", { spec });
export const inspectAppSource = (path) => invoke("inspect_app_source", { path });
