<script>
  import { addRepoSource, fetchRepo } from "../lib/api.js";
  import { hostFromSourceUrl } from "../lib/url.js";

  let { url, onclose } = $props();

  /** @type {"loading" | "ready" | "adding" | "done" | "error"} */
  let phase = $state("loading");
  let catalog = $state(null);
  let errorMsg = $state("");

  $effect(() => {
    if (url) validate(url);
  });

  async function validate(sourceUrl) {
    phase = "loading";
    catalog = null;
    errorMsg = "";
    try {
      catalog = await fetchRepo(sourceUrl);
      phase = "ready";
    } catch (e) {
      errorMsg = typeof e === "string" ? e : String(e);
      phase = "error";
    }
  }

  async function addSource() {
    if (!catalog || phase !== "ready") return;
    phase = "adding";
    errorMsg = "";
    try {
      await addRepoSource(url);
      phase = "done";
    } catch (e) {
      errorMsg = typeof e === "string" ? e : String(e);
      phase = "error";
    }
  }

  function close(added = false) {
    onclose?.({ added });
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === "Escape" && phase !== "adding") close(false);
  }}
/>

<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
<div
  class="backdrop"
  role="presentation"
  onclick={(e) => {
    if (e.target === e.currentTarget && phase !== "adding") close(false);
  }}
>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="repo-title">
    {#if phase === "loading"}
      <div class="center">
        <div class="spinner" aria-hidden="true"></div>
        <p class="muted">Checking repository...</p>
      </div>
    {:else if phase === "done"}
      <h1 id="repo-title" class="ok-title">Source added</h1>
      <p>{catalog?.name || "OpenInstall repo"} is now available in the Store.</p>
      <footer class="actions">
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={() => close(true)}>Open Store</button>
      </footer>
    {:else if phase === "error"}
      <h1 id="repo-title">Could not add source</h1>
      <p class="source">{url}</p>
      <p class="error" role="alert">{errorMsg}</p>
      <footer class="actions">
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={() => close(false)}>Close</button>
      </footer>
    {:else if catalog}
      <p class="eyebrow">{hostFromSourceUrl(catalog.sourceUrl)}</p>
      <h1 id="repo-title">Add Store Source</h1>
      <p class="name">{catalog.name}</p>
      {#if catalog.description}
        <p>{catalog.description}</p>
      {/if}

      <dl class="details">
        <dt>Apps</dt>
        <dd>{catalog.apps.length}</dd>
        <dt>Source</dt>
        <dd><code>{catalog.sourceUrl}</code></dd>
        <dt>Catalog</dt>
        <dd><code>{catalog.manifestUrl}</code></dd>
      </dl>

      <p class="hint">
        Adding a source only makes its catalog browsable. Every app still goes
        through package verification and a separate Install click.
      </p>
      <footer class="actions">
        <button type="button" onclick={() => close(false)} disabled={phase === "adding"}>Cancel</button>
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={addSource} disabled={phase !== "ready"}>
          {phase === "adding" ? "Adding..." : "Add Source"}
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
    max-width: 540px;
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
    font-size: 1.25rem;
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
  .eyebrow,
  .source {
    color: var(--muted);
    font-size: 0.82rem;
    font-weight: 700;
  }
  .source {
    word-break: break-all;
  }
  .name {
    font-weight: 700;
    font-size: 1.05rem;
  }
  .ok-title {
    color: var(--ok);
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
  .hint {
    color: var(--muted);
    font-size: 0.86rem;
    line-height: 1.4;
  }
  .actions {
    display: flex;
    gap: 0.6rem;
    align-items: center;
  }
  .spacer {
    flex: 1 1 auto;
  }
</style>
