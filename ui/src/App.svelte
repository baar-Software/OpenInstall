<script>
  // OpenInstall top-level shell: a Launchpad of installed apps, a package
  // Creator, and the consent modal that appears whenever a package is resolved
  // (from a deep link, the manual bar, or an update check).
  //
  // No auto-install: a deep link only OPENS the consent modal (resolve is
  // side-effect-free). confirm_install is reached solely from the modal's Install
  // button (invariants #1/#6).
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { getCurrent as getCurrentDeepLink, onOpenUrl } from "@tauri-apps/plugin-deep-link";

  import Launchpad from "./views/Launchpad.svelte";
  import Repos from "./views/Repos.svelte";
  import CreatePackage from "./views/CreatePackage.svelte";
  import Consent from "./views/Consent.svelte";
  import RepoConsent from "./views/RepoConsent.svelte";
  import Logo from "./components/Logo.svelte";
  import { getSettings, setDeveloperMode } from "./lib/api.js";
  import { repoSourceFromLink, urlFromQuery } from "./lib/url.js";

  /** @type {"home" | "repos" | "create"} */
  let view = $state("home");
  /** A URL to resolve in the consent modal, or null when closed. */
  let consentUrl = $state(null);
  let repoUrl = $state(null);
  /** Bumped to force the Launchpad to reload after an install. */
  let launchpadKey = $state(0);
  let storeKey = $state(0);
  let developerMode = $state(false);

  function startConsent(url) {
    if (!url) return;
    const source = repoSourceFromLink(url);
    if (source) {
      repoUrl = source;
    } else {
      consentUrl = url;
    }
  }

  function onConsentClose({ installed } = {}) {
    consentUrl = null;
    if (installed) {
      view = "home";
      launchpadKey += 1; // remount Launchpad to show the new app
    }
  }

  function onRepoClose({ added } = {}) {
    repoUrl = null;
    if (added) {
      view = "repos";
      storeKey += 1;
    }
  }

  async function toggleDevMode() {
    try {
      const s = await setDeveloperMode(!developerMode);
      developerMode = s.developerMode;
    } catch {
      // ignore; toggle stays as-is
    }
  }

  onMount(() => {
    // Load settings.
    getSettings()
      .then((s) => (developerMode = !!s.developerMode))
      .catch(() => {});

    // Deep-link sources -> open the consent modal (never auto-install).
    const fromQuery = urlFromQuery();
    if (fromQuery) startConsent(fromQuery);

    getCurrentDeepLink()
      .then((cur) => {
        if (cur && cur.length > 0) startConsent(cur[0]);
      })
      .catch(() => {});

    let un1 = () => {};
    let un2 = () => {};
    onOpenUrl((urls) => {
      if (urls && urls.length > 0) startConsent(urls[0]);
    })
      .then((u) => (un1 = u))
      .catch(() => {});
    listen("deep-link-url", (e) => {
      if (typeof e.payload === "string") startConsent(e.payload);
    })
      .then((u) => (un2 = u))
      .catch(() => {});

    return () => {
      un1();
      un2();
    };
  });
</script>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <span class="logo"><Logo size={20} /></span>
      <div>
        <span class="title">OpenInstall</span>
        <span class="caption">App Store for .oip</span>
      </div>
    </div>

    <nav class="tabs" aria-label="Primary">
      <button class:active={view === "home"} class="ghost" type="button" onclick={() => (view = "home")}>
        <span class="nav-dot"></span>
        Launchpad
      </button>
      <button class:active={view === "repos"} class="ghost" type="button" onclick={() => (view = "repos")}>
        <span class="nav-dot"></span>
        Store
      </button>
      <button class:active={view === "create"} class="ghost" type="button" onclick={() => (view = "create")}>
        <span class="nav-dot"></span>
        Create
      </button>
    </nav>

    <label class="devmode" title="Allow openinstall://localhost links for local development. Verification and consent are unchanged.">
      <input type="checkbox" checked={developerMode} onchange={toggleDevMode} />
      <span>Developer mode</span>
    </label>
  </aside>

  <main class="content">
    {#if view === "home"}
      {#key launchpadKey}
        <Launchpad onresolve={startConsent} />
      {/key}
    {:else if view === "repos"}
      {#key storeKey}
        <Repos onresolve={startConsent} />
      {/key}
    {:else}
      <CreatePackage />
    {/if}
  </main>
</div>

{#if consentUrl}
  <Consent url={consentUrl} onclose={onConsentClose} />
{/if}

{#if repoUrl}
  <RepoConsent url={repoUrl} onclose={onRepoClose} />
{/if}

<style>
  .shell {
    width: 100%;
    margin: 0;
    min-height: 100vh;
    display: grid;
    grid-template-columns: 260px minmax(0, 1fr);
  }

  .sidebar {
    position: sticky;
    top: 0;
    height: 100vh;
    padding: 1.35rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 1.15rem;
    background: var(--glass);
    border-right: 1px solid var(--border);
    backdrop-filter: blur(28px) saturate(160%);
  }

  .brand {
    display: grid;
    grid-template-columns: 38px minmax(0, 1fr);
    align-items: center;
    gap: 0.65rem;
    padding: 0.35rem 0.45rem;
  }

  .brand > div {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .logo {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-2);
    border: 1px solid var(--border);
    color: var(--accent);
  }

  .title {
    font-size: 1.02rem;
    font-weight: 750;
    letter-spacing: 0;
  }

  .caption {
    color: var(--muted);
    font-size: 0.78rem;
    margin-top: -0.05rem;
  }

  .tabs {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .tabs button {
    width: 100%;
    justify-content: flex-start;
    min-height: 38px;
    border-radius: 10px;
    padding: 0.45rem 0.65rem;
    color: var(--muted);
    font-weight: 600;
  }

  .tabs button:hover {
    color: var(--fg);
  }

  .tabs .active,
  .tabs .active:hover {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .nav-dot {
    width: 8px;
    height: 8px;
    border-radius: 999px;
    background: currentColor;
    opacity: 0.35;
  }

  .tabs .active .nav-dot {
    opacity: 1;
  }

  .devmode {
    margin-top: auto;
    display: flex;
    align-items: center;
    gap: 0.45rem;
    color: var(--muted);
    font-size: 0.84rem;
    cursor: pointer;
    padding: 0.75rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--surface);
  }

  .devmode input {
    width: auto;
  }

  .content {
    min-width: 0;
    padding: 2.2rem clamp(2rem, 4vw, 4.6rem) 3rem;
    max-width: none;
  }

  @media (max-width: 820px) {
    .shell {
      display: block;
    }

    .sidebar {
      position: sticky;
      top: 0;
      z-index: 10;
      height: auto;
      flex-direction: row;
      align-items: center;
      padding: 0.65rem;
      border-right: 0;
      border-bottom: 1px solid var(--border);
    }

    .caption,
    .devmode span {
      display: none;
    }

    .tabs {
      flex-direction: row;
      flex: 1;
      overflow-x: auto;
    }

    .tabs button {
      flex: 1 0 auto;
      justify-content: center;
    }

    .nav-dot {
      display: none;
    }

    .devmode {
      margin-top: 0;
      padding: 0.45rem;
    }

    .content {
      padding: 1.35rem 1rem 2rem;
    }
  }
</style>
