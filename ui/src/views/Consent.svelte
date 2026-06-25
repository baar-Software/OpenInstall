<script>
  import TrustBadge from "../components/TrustBadge.svelte";
  import { acknowledgeRisk, confirmInstall, resolveOip } from "../lib/api.js";
  import { canInstall, requiresOverride } from "../lib/consent.js";
  import { formatBytes } from "../lib/format.js";
  import { hostFromSourceUrl } from "../lib/url.js";

  let { url, onclose } = $props();

  /** @type {"resolving" | "ready" | "installing" | "done" | "error"} */
  let phase = $state("resolving");
  let result = $state(null);
  let errorMsg = $state("");
  let installResult = $state(null);
  let overridden = $state(false);
  let showDetails = $state(false);

  const host = $derived(result ? hostFromSourceUrl(result.sourceUrl) : "");
  const needsOverride = $derived(result ? requiresOverride({ trust: result.trust }) : false);
  const installEnabled = $derived(
    !!result && phase === "ready" && canInstall({ trust: result.trust, overridden }),
  );

  $effect(() => {
    if (url) doResolve(url);
  });

  async function doResolve(u) {
    phase = "resolving";
    errorMsg = "";
    result = null;
    installResult = null;
    overridden = false;
    showDetails = false;
    try {
      result = await resolveOip(u);
      phase = "ready";
    } catch (e) {
      errorMsg = typeof e === "string" ? e : String(e);
      phase = "error";
    }
  }

  async function onInstall() {
    if (!result || !installEnabled) return;
    phase = "installing";
    errorMsg = "";
    try {
      if (needsOverride) {
        await acknowledgeRisk(result.installToken);
      }
      installResult = await confirmInstall(result.installToken);
      phase = "done";
    } catch (e) {
      errorMsg = typeof e === "string" ? e : String(e);
      phase = "error";
    }
  }

  function close(installed = false) {
    onclose?.({ installed });
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === "Escape" && phase !== "installing") close(false);
  }}
/>

<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
<div
  class="backdrop"
  role="presentation"
  onclick={(e) => {
    if (e.target === e.currentTarget && phase !== "installing") close(false);
  }}
>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="dlg-title">
    {#if phase === "resolving"}
      <div class="center">
        <div class="spinner" aria-hidden="true"></div>
        <p class="muted">Resolving and verifying package...</p>
      </div>
    {:else if phase === "error" && !result}
      <h1 id="dlg-title">Could not resolve package</h1>
      <p class="error" role="alert">{errorMsg}</p>
      <footer class="actions">
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={() => close(false)}>Close</button>
      </footer>
    {:else if phase === "done" && installResult}
      {#if installResult.success}
        <h1 id="dlg-title" class="ok-title">Installed</h1>
      {:else}
        <h1 id="dlg-title" class="bad-title">Install failed</h1>
      {/if}
      <p>{installResult.message}</p>
      {#if installResult.exitCode !== null && installResult.exitCode !== undefined}
        <p class="muted">Exit code: {installResult.exitCode}</p>
      {/if}
      <footer class="actions">
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={() => close(installResult.success)}>Done</button>
      </footer>
    {:else if result}
      <header class="head">
        <p class="eyebrow">{host}</p>
        <h1 id="dlg-title">Install {result.name}</h1>
        <p class="muted byline">{result.version} by {result.publisher}</p>
      </header>

      <TrustBadge trust={result.trust} keyFingerprint={result.keyFingerprint} />

      <section class="checks" aria-label="Verification results">
        <div class="check ok">
          <span class="label">Install mode</span>
          <span class="value">Per-user, no admin rights</span>
        </div>
        <div class="check ok">
          <span class="label">Package</span>
          <span class="value">Hashes and manifest verified</span>
        </div>
      </section>

      {#if needsOverride}
        <label class="override">
          <input type="checkbox" bind:checked={overridden} />
          <span>I understand the publisher key changed and want to install anyway.</span>
        </label>
      {/if}

      <p class="source" title={result.sourceUrl}>
        <span>Source</span>
        <a href={result.sourceUrl} rel="noreferrer noopener" target="_blank">{result.sourceUrl}</a>
      </p>

      {#if showDetails}
        <dl class="details">
          <dt>App id</dt>
          <dd><code>{result.id}</code></dd>
          <dt>Homepage</dt>
          <dd>
            {#if result.homepage}
              <a href={result.homepage} rel="noreferrer noopener" target="_blank">{result.homepage}</a>
            {:else}<span class="muted">(none)</span>{/if}
          </dd>
          <dt>Trust</dt>
          <dd><code>{result.trust}</code></dd>
          <dt>Key fingerprint</dt>
          <dd><code>{result.keyFingerprint || "(none)"}</code></dd>
          <dt>Package size</dt>
          <dd>{formatBytes(result.payloadSize)}</dd>
        </dl>
      {/if}

      {#if phase === "installing"}
        <p class="muted" role="status">Installing...</p>
      {/if}
      {#if errorMsg}
        <p class="error" role="alert">{errorMsg}</p>
      {/if}

      <footer class="actions">
        <button class="ghost" type="button" onclick={() => (showDetails = !showDetails)} aria-expanded={showDetails}>
          {showDetails ? "Hide details" : "Details"}
        </button>
        <span class="spacer"></span>
        <button type="button" onclick={() => close(false)} disabled={phase === "installing"}>Cancel</button>
        <button
          class="primary {needsOverride ? 'danger' : ''}"
          type="button"
          onclick={onInstall}
          disabled={!installEnabled}
        >
          {phase === "installing" ? "Installing..." : "Install"}
        </button>
      </footer>
    {/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.48);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
    z-index: 100;
  }
  .modal {
    width: 100%;
    max-width: 560px;
    max-height: min(760px, calc(100vh - 2rem));
    overflow: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.1rem;
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
  }
  h1,
  p {
    margin: 0;
  }
  h1 {
    font-size: 1.28rem;
    line-height: 1.2;
  }
  .center {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.8rem;
    text-align: center;
    padding: 1.5rem 0;
  }
  .spinner {
    width: 28px;
    height: 28px;
    border-radius: 999px;
    border: 3px solid var(--surface-3);
    border-top-color: var(--accent);
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .head {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .eyebrow {
    color: var(--muted);
    font-size: 0.82rem;
    font-weight: 700;
    text-transform: uppercase;
  }
  .byline {
    font-size: 0.94rem;
  }
  .checks {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.55rem;
  }
  .check {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.65rem;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    min-width: 0;
  }
  .check .label {
    color: var(--muted);
    font-size: 0.76rem;
    font-weight: 700;
    text-transform: uppercase;
  }
  .check .value {
    font-weight: 650;
    word-break: break-word;
  }
  .check.ok {
    border-color: color-mix(in srgb, var(--ok) 55%, var(--border));
  }
  .check.ok .value {
    color: var(--ok);
  }
  .override {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
    padding: 0.65rem 0.75rem;
    border: 1px solid var(--bad);
    border-radius: var(--radius);
    background: var(--bad-bg);
    color: var(--bad);
  }
  .override input {
    margin-top: 0.15rem;
    width: auto;
  }
  .source {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 0.55rem;
    font-size: 0.86rem;
  }
  .source span {
    color: var(--muted);
    font-weight: 700;
  }
  .source a {
    overflow-wrap: anywhere;
  }
  .ok-title {
    color: var(--ok);
  }
  .bad-title {
    color: var(--bad);
  }
  .details {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.3rem 0.8rem;
    margin: 0;
    padding: 0.7rem 0.8rem;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 0.85rem;
  }
  .details dt {
    font-weight: 600;
    color: var(--muted);
  }
  .details dd {
    margin: 0;
    word-break: break-all;
  }
  .actions {
    display: flex;
    gap: 0.6rem;
    align-items: center;
  }
  .spacer {
    flex: 1 1 auto;
  }

  @media (max-width: 560px) {
    .checks {
      grid-template-columns: 1fr;
    }
    .actions {
      flex-wrap: wrap;
    }
    .actions button {
      flex: 1 1 auto;
    }
  }
</style>
