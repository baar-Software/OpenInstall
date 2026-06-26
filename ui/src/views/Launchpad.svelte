<script>
  import { onMount } from "svelte";
  import { ask } from "@tauri-apps/plugin-dialog";
  import { backfillIcons, launchApp, listInstalled, uninstallApp } from "../lib/api.js";
  import { formatUnixSeconds } from "../lib/format.js";
  import { hostFromSourceUrl } from "../lib/url.js";
  import Logo from "../components/Logo.svelte";

  let { onresolve } = $props();

  let apps = $state([]);
  let loading = $state(true);
  let error = $state("");
  let manualUrl = $state("");
  let query = $state("");
  let busyId = $state("");

  const verifiedCount = $derived(
    apps.filter((app) => app.trust === "Verified" || app.trust === "VerifiedNewPublisher").length,
  );
  const visibleApps = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return apps;
    return apps.filter((app) =>
      [app.name, app.publisher, app.version, app.id, app.sourceUrl]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(q)),
    );
  });

  onMount(load);

  async function load() {
    loading = true;
    error = "";
    try {
      apps = await listInstalled();
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      loading = false;
    }
    // Fill in any missing icons in the background — never blocks first paint.
    if (apps.some((a) => !a.icon)) {
      backfillIcons()
        .then((updated) => {
          apps = updated;
        })
        .catch(() => {});
    }
  }

  function trustPill(trust) {
    switch (trust) {
      case "Verified":
      case "VerifiedNewPublisher":
        return { text: "Verified", cls: "ok" };
      case "PublisherChanged":
        return { text: "Publisher changed", cls: "bad" };
      default:
        return { text: "Unverified", cls: "warn" };
    }
  }

  function initials(name) {
    return (name || "?").trim().slice(0, 1).toUpperCase();
  }

  async function onLaunch(app) {
    busyId = app.id;
    error = "";
    try {
      await launchApp(app.id);
    } catch (e) {
      error = `Could not launch ${app.name}: ${typeof e === "string" ? e : e}`;
    } finally {
      busyId = "";
    }
  }

  async function onUninstall(app) {
    const confirmed = await ask(
      `Delete ${app.name} and all of its files?\n\nThis removes the app from your computer and cannot be undone.`,
      { title: "Uninstall app", kind: "warning", okLabel: "Uninstall", cancelLabel: "Cancel" },
    );
    if (!confirmed) return;
    busyId = app.id;
    error = "";
    try {
      await uninstallApp(app.id);
      await load();
    } catch (e) {
      error = `Could not uninstall ${app.name}: ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busyId = "";
    }
  }

  function onManual(e) {
    e.preventDefault();
    const u = manualUrl.trim();
    if (u) onresolve?.(u);
  }
</script>

<div class="wrap">
  <header class="view-head">
    <div>
      <h1 class="view-title">Launchpad</h1>
      <p class="view-subtitle">
        {apps.length} installed {apps.length === 1 ? "app" : "apps"} · {verifiedCount} verified
      </p>
    </div>
    <button type="button" class="subtle" onclick={load} disabled={loading}>
      {loading ? "Refreshing…" : "Refresh"}
    </button>
  </header>

  <form class="installbar panel" onsubmit={onManual}>
    <svg class="link-glyph" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7">
      <path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" stroke-linecap="round" stroke-linejoin="round" />
      <path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <input
      type="text"
      bind:value={manualUrl}
      placeholder="Paste an openinstall:// link to verify & install…"
      aria-label="openinstall URL"
    />
    <button type="submit" class="primary" disabled={!manualUrl.trim()}>Verify</button>
  </form>

  {#if error}
    <p class="error" role="alert">{error}</p>
  {/if}

  {#if loading}
    <div class="empty-state"><p class="muted">Loading installed apps…</p></div>
  {:else if apps.length === 0}
    <div class="empty-state hero">
      <div class="hero-mark"><Logo size={40} /></div>
      <h2>No apps yet</h2>
      <p class="muted">
        Apps you install from <code>openinstall://</code> links appear here. Paste a
        link above, browse the <strong>Store</strong>, or build your own in
        <strong>Create</strong>.
      </p>
    </div>
  {:else}
    {#if apps.length > 5}
      <div class="tools">
        <input type="text" bind:value={query} placeholder="Search apps" aria-label="Search installed apps" />
      </div>
    {/if}

    {#if visibleApps.length === 0}
      <div class="empty-state">
        <h2>No matches</h2>
        <p class="muted">Try another app name, publisher, version, or bundle id.</p>
      </div>
    {:else}
      <div class="grid">
        {#each visibleApps as app (app.id)}
          {@const pill = trustPill(app.trust)}
          <article class="tile panel">
            <button
              class="forget"
              title="Uninstall {app.name} (deletes the app)"
              aria-label="Uninstall {app.name}"
              onclick={() => onUninstall(app)}
              disabled={busyId === app.id}>×</button
            >
            <div class="head">
              {#if app.icon}
                <img class="icon" src={app.icon} alt="" draggable="false" />
              {:else}
                <div class="icon lettermark">{initials(app.name)}</div>
              {/if}
              <div class="ident">
                <div class="name" title={app.name}>{app.name}</div>
                <div class="meta muted" title={app.publisher}>{app.publisher}</div>
                <div class="ver muted">{app.version}</div>
              </div>
            </div>

            <div class="rowline">
              <span class="pill {pill.cls}">{pill.text}</span>
              {#if app.installedAt}
                <span class="date muted">{formatUnixSeconds(app.installedAt)}</span>
              {/if}
            </div>

            <div class="tile-actions">
              {#if app.launchTarget}
                <button class="primary" type="button" onclick={() => onLaunch(app)} disabled={busyId === app.id}>
                  {busyId === app.id ? "Launching…" : "Launch"}
                </button>
              {/if}
              {#if app.sourceUrl}
                <button class="ghost" type="button" title="Re-check the source for an update" onclick={() => onresolve?.(app.sourceUrl)}>
                  Check
                </button>
              {/if}
              {#if app.homepage}
                <a class="ghost-link" href={app.homepage} rel="noreferrer noopener" target="_blank">Web</a>
              {/if}
            </div>
          </article>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .wrap {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .installbar {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.55rem 0.6rem 0.55rem 0.85rem;
  }
  .link-glyph {
    width: 18px;
    height: 18px;
    color: var(--muted);
    flex: 0 0 auto;
  }
  .installbar input {
    border: 0;
    background: transparent;
    box-shadow: none;
    padding-left: 0;
  }
  .installbar input:focus-visible {
    outline: none;
  }
  .installbar button {
    flex: 0 0 auto;
  }

  .tools {
    max-width: 320px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 0.9rem;
  }

  .tile {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
    padding: 1.05rem;
    transition:
      transform 160ms ease,
      border-color 160ms ease,
      box-shadow 160ms ease;
  }
  .tile:hover {
    transform: translateY(-3px);
    border-color: var(--border-strong);
    box-shadow: var(--shadow);
  }

  .head {
    display: flex;
    gap: 0.8rem;
    align-items: center;
    min-width: 0;
  }
  .icon {
    width: 52px;
    height: 52px;
    border-radius: 14px;
    flex: 0 0 auto;
    object-fit: contain;
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .lettermark {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
    font-size: 1.3rem;
    font-weight: 700;
    background: var(--surface-3);
  }
  .ident {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 0.05rem;
    padding-right: 1rem;
  }
  .name {
    font-weight: 650;
    font-size: 1rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta,
  .ver,
  .date {
    font-size: 0.82rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .forget {
    position: absolute;
    top: 0.55rem;
    right: 0.55rem;
    width: 1.5rem;
    height: 1.5rem;
    min-height: 0;
    padding: 0;
    line-height: 1;
    border-color: transparent;
    background: transparent;
    color: var(--muted);
    font-size: 1.05rem;
  }
  .forget:hover {
    background: var(--surface-2);
    color: var(--bad);
  }

  .rowline {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .pill {
    font-size: 0.72rem;
    font-weight: 650;
    padding: 0.12rem 0.55rem;
    border-radius: 999px;
  }
  .pill.ok {
    color: var(--ok);
    background: var(--ok-soft);
  }
  .pill.bad {
    color: var(--bad);
    background: var(--bad-bg);
  }
  .pill.warn {
    color: var(--warn);
    background: var(--warn-soft);
  }

  .tile-actions {
    margin-top: auto;
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .tile-actions .primary {
    flex: 1 1 auto;
  }
  .tile-actions button,
  .ghost-link {
    min-height: 32px;
    padding: 0.35rem 0.7rem;
    font-size: 0.85rem;
  }
  .ghost-link {
    display: inline-flex;
    align-items: center;
    border-radius: var(--radius-sm);
    text-decoration: none;
    color: var(--muted);
  }
  .ghost-link:hover {
    background: var(--surface-2);
  }

  .hero {
    padding: 4rem 1.5rem;
  }
  .hero-mark {
    width: 56px;
    height: 56px;
    margin: 0 auto 1rem;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-2);
    border: 1px solid var(--border);
    color: var(--accent);
  }

  @media (max-width: 640px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
