<script>
  import { onMount } from "svelte";
  import { addRepoSource, fetchRepo, listRepoSources, removeRepoSource } from "../lib/api.js";
  import { hostFromSourceUrl } from "../lib/url.js";

  let { onresolve } = $props();

  let sources = $state([]);
  let catalogs = $state([]);
  let sourceUrl = $state("");
  let query = $state("");
  let loading = $state(true);
  let busy = $state(false);
  let error = $state("");

  const totalApps = $derived(
    catalogs.reduce((sum, entry) => sum + (entry.catalog?.apps.length || 0), 0),
  );
  const healthyRepos = $derived(catalogs.filter((entry) => entry.catalog && !entry.error).length);
  const visibleCatalogs = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return catalogs;

    return catalogs
      .map((entry) => {
        if (!entry.catalog) return entry;
        const apps = entry.catalog.apps.filter((app) => appMatches(app, entry.catalog, q));
        return { ...entry, catalog: { ...entry.catalog, apps } };
      })
      .filter((entry) => entry.error || (entry.catalog?.apps.length || 0) > 0);
  });

  onMount(load);

  async function load() {
    loading = true;
    error = "";
    try {
      sources = await listRepoSources();
      await refreshCatalogs();
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      loading = false;
    }
  }

  async function refreshCatalogs() {
    catalogs = await Promise.all(
      sources.map(async (source) => {
        try {
          return { source, catalog: await fetchRepo(source.url), error: "" };
        } catch (e) {
          return { source, catalog: null, error: typeof e === "string" ? e : String(e) };
        }
      }),
    );
  }

  async function addSource(e) {
    e.preventDefault();
    const url = sourceUrl.trim();
    if (!url) return;
    busy = true;
    error = "";
    try {
      sources = await addRepoSource(url);
      sourceUrl = "";
      await refreshCatalogs();
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }

  async function removeSource(url) {
    busy = true;
    error = "";
    try {
      sources = await removeRepoSource(url);
      await refreshCatalogs();
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }

  async function refresh() {
    busy = true;
    error = "";
    try {
      await refreshCatalogs();
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }

  function appMatches(app, catalog, q) {
    return [
      app.name,
      app.description,
      app.bundleIdentifier,
      app.latest,
      catalog.name,
      catalog.sourceUrl,
      ...(app.versions || []).map((version) => version.version),
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(q));
  }

  function appInitial(name) {
    return (name || "?").trim().slice(0, 1).toUpperCase();
  }

  function latestVersion(app) {
    return app.versions?.find((v) => v.isLatest) || app.versions?.[0] || null;
  }
</script>

<div class="store">
  <header class="view-head">
    <div>
      <h1 class="view-title">Store</h1>
      <p class="view-subtitle">
        {totalApps} {totalApps === 1 ? "app" : "apps"} from {healthyRepos} of
        {sources.length} {sources.length === 1 ? "source" : "sources"}.
      </p>
    </div>
    <button type="button" class="subtle" onclick={refresh} disabled={busy || sources.length === 0}>
      {busy ? "Refreshing..." : "Refresh"}
    </button>
  </header>

  <section class="source-panel panel">
    <div class="source-intro">
      <span class="eyebrow">Store sources</span>
      <strong>Curated app catalogs</strong>
    </div>
    <form class="sourcebar" onsubmit={addSource}>
      <label class="source-field">
        <span>Repository source</span>
        <input
          type="text"
          bind:value={sourceUrl}
          placeholder="https://example.com/openinstall"
          aria-label="OpenInstall repo URL"
        />
      </label>
      <button type="submit" class="primary" disabled={busy || !sourceUrl.trim()}>Add Source</button>
    </form>
    {#if sources.length > 0}
      <div class="source-strip">
        {#each catalogs as entry (entry.source.url)}
          <div class="source-chip" title={entry.source.url}>
            <span class:online={entry.catalog && !entry.error} class="dot"></span>
            <span>{entry.catalog?.name || hostFromSourceUrl(entry.source.url)}</span>
          </div>
        {/each}
      </div>
    {/if}
  </section>

  {#if sources.length > 0}
    <div class="searchline">
      <input
        class="search"
        type="text"
        bind:value={query}
        placeholder="Search apps, versions, bundle identifiers"
        aria-label="Search store"
      />
    </div>
  {/if}

  {#if error}
    <p class="error" role="alert">{error}</p>
  {/if}

  {#if loading}
    <div class="empty-state"><p class="muted">Loading sources...</p></div>
  {:else if sources.length === 0}
    <div class="empty-state">
      <h2>No sources</h2>
      <p class="muted">Add an OpenInstall repo URL to populate the Store.</p>
    </div>
  {:else if visibleCatalogs.length === 0}
    <div class="empty-state">
      <h2>No matches</h2>
      <p class="muted">Try a different app name, version, or bundle identifier.</p>
    </div>
  {:else}
    <div class="catalogs">
      {#each visibleCatalogs as entry (entry.source.url)}
        <section class="catalog">
          <div class="catalog-head">
            <div class="catalog-meta">
              <div class="catalog-title">
                <h2>{entry.catalog?.name || entry.source.url}</h2>
                {#if entry.catalog}
                  <span class="status ok">online</span>
                {:else}
                  <span class="status bad">offline</span>
                {/if}
              </div>
              {#if entry.catalog?.description}
                <p class="muted">{entry.catalog.description}</p>
              {/if}
              <p class="muted small url">{entry.source.url}</p>
            </div>
            <button
              type="button"
              class="ghost"
              disabled={busy}
              onclick={() => removeSource(entry.source.url)}
            >
              Remove
            </button>
          </div>

          {#if entry.error}
            <p class="error">{entry.error}</p>
          {:else if entry.catalog.apps.length === 0}
            <div class="empty-state compact"><p class="muted">No apps in this source.</p></div>
          {:else}
            <div class="apps">
              {#each entry.catalog.apps as app (app.bundleIdentifier)}
                {@const latest = latestVersion(app)}
                <article class="app panel">
                  {#if app.iconUrl}
                    <img class="icon-img" src={app.iconUrl} alt="" />
                  {:else}
                    <div class="icon-fallback">{appInitial(app.name)}</div>
                  {/if}

                  <div class="app-main">
                    <div class="app-top">
                      <div class="app-id">
                        <h3>{app.name}</h3>
                        <p class="muted small mono">{app.bundleIdentifier}</p>
                      </div>
                      {#if latest}
                        <button class="primary install" type="button" onclick={() => onresolve?.(latest.installUrl)}>
                          Get
                        </button>
                      {/if}
                    </div>

                    {#if app.description}
                      <p class="desc">{app.description}</p>
                    {/if}

                    {#if app.screenshotUrls.length > 0}
                      <div class="shots">
                        {#each app.screenshotUrls.slice(0, 3) as shot}
                          <img src={shot} alt="" loading="lazy" />
                        {/each}
                      </div>
                    {/if}

                    <div class="versions" aria-label="Available versions">
                      {#each app.versions.slice(0, 6) as version (version.version)}
                        <button
                          type="button"
                          class:latest={version.isLatest}
                          onclick={() => onresolve?.(version.installUrl)}
                          title={version.installUrl}
                        >
                          {version.version}{version.isLatest ? " latest" : ""}
                        </button>
                      {/each}
                    </div>
                  </div>
                </article>
              {/each}
            </div>
          {/if}
        </section>
      {/each}
    </div>
  {/if}
</div>

<style>
  .store {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .source-panel {
    padding: 1rem;
    display: grid;
    grid-template-columns: 190px minmax(0, 1fr);
    gap: 0.75rem;
    align-items: end;
    animation: rise-in 420ms ease both;
  }
  .source-intro {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }
  .eyebrow {
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .sourcebar {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.7rem;
    align-items: end;
  }
  .source-field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }
  .source-field span {
    color: var(--muted);
    font-size: 0.82rem;
    font-weight: 600;
  }
  .source-strip {
    grid-column: 1 / -1;
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .source-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    max-width: 260px;
    padding: 0.22rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-2);
    backdrop-filter: blur(18px);
    color: var(--muted);
    font-size: 0.82rem;
  }
  .source-chip span:last-child {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dot {
    flex: none;
    width: 0.48rem;
    height: 0.48rem;
    border-radius: 999px;
    background: var(--bad);
  }
  .dot.online {
    background: var(--ok);
  }
  .searchline {
    max-width: 420px;
  }
  .catalogs,
  .apps {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .catalog {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    padding-top: 0.2rem;
  }
  .catalog + .catalog {
    border-top: 1px solid var(--border);
    padding-top: 1.2rem;
  }
  .catalog-head,
  .catalog-title,
  .app-top {
    display: flex;
    gap: 0.75rem;
  }
  .catalog-head,
  .app-top {
    justify-content: space-between;
    align-items: flex-start;
  }
  .catalog-meta {
    min-width: 0;
  }
  .catalog h2,
  .app h3,
  p {
    margin: 0;
  }
  .catalog h2 {
    font-size: 1.18rem;
  }
  .catalog-title {
    align-items: center;
    flex-wrap: wrap;
  }
  .status {
    border: 1px solid currentColor;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 800;
    padding: 0.08rem 0.42rem;
    text-transform: uppercase;
  }
  .status.ok {
    color: var(--ok);
  }
  .status.bad {
    color: var(--bad);
  }
  .small {
    font-size: 0.82rem;
  }
  .compact {
    padding: 1.25rem;
  }
  .app {
    display: grid;
    grid-template-columns: 76px minmax(0, 1fr);
    gap: 1rem;
    padding: 1rem;
    overflow: hidden;
    position: relative;
    transition:
      transform 180ms ease,
      border-color 180ms ease,
      box-shadow 180ms ease;
  }
  .app:hover {
    transform: translateY(-3px);
    border-color: var(--border-strong);
    box-shadow: var(--shadow), var(--highlight);
  }
  .icon-img,
  .icon-fallback {
    position: relative;
    width: 76px;
    height: 76px;
    border-radius: 18px;
    object-fit: cover;
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .icon-fallback {
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-3);
    color: var(--muted);
    font-size: 1.7rem;
    font-weight: 700;
  }
  .app-main,
  .app-id {
    position: relative;
    min-width: 0;
  }
  .app-main {
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
  }
  .app-id h3,
  .app-id p {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .app-id h3 {
    font-size: 1.12rem;
  }
  .desc {
    line-height: 1.45;
    color: color-mix(in srgb, var(--fg) 86%, var(--muted));
  }
  .shots {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.5rem;
  }
  .shots img {
    width: 100%;
    aspect-ratio: 16 / 9;
    object-fit: cover;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: var(--surface-2);
    box-shadow: 0 10px 20px rgba(20, 40, 70, 0.08);
  }
  .versions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .versions button {
    min-height: 30px;
    padding: 0.28rem 0.58rem;
    font-size: 0.82rem;
  }
  .versions .latest {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-soft);
  }
  .install {
    min-width: 72px;
  }

  @media (max-width: 720px) {
    .sourcebar,
    .catalog-head,
    .app-top {
      grid-template-columns: 1fr;
      flex-direction: column;
      align-items: stretch;
    }
    .sourcebar {
      display: grid;
    }
    .source-panel {
      grid-template-columns: 1fr;
    }
    .searchline {
      max-width: none;
    }
    .app {
      grid-template-columns: 48px minmax(0, 1fr);
    }
    .icon-img,
    .icon-fallback {
      width: 48px;
      height: 48px;
      border-radius: 13px;
    }
    .shots {
      grid-template-columns: 1fr;
    }
  }
</style>
