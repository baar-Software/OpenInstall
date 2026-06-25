<script>
  let { trust, keyFingerprint = "" } = $props();

  const fp = $derived(keyFingerprint ? keyFingerprint : "(unknown)");
</script>

{#if trust === "Verified"}
  <div class="badge verified" role="status">
    <span class="mark" aria-hidden="true">OK</span>
    <span class="text">
      <strong>Verified package</strong>
      <span class="sub">Publisher key <code>{fp}</code></span>
    </span>
  </div>
{:else if trust === "VerifiedNewPublisher"}
  <div class="badge new-publisher" role="status">
    <span class="mark" aria-hidden="true">NEW</span>
    <span class="text">
      <strong>Verified new publisher</strong>
      <span class="sub">First install from this publisher{#if keyFingerprint}: <code>{fp}</code>{/if}</span>
    </span>
  </div>
{:else if trust === "PublisherChanged"}
  <div class="badge publisher-changed" role="alert">
    <span class="mark" aria-hidden="true">!</span>
    <span class="text">
      <strong>Publisher key changed</strong>
      <span class="sub">This app id was previously signed by a different key{#if keyFingerprint}: <code>{fp}</code>{/if}</span>
    </span>
  </div>
{:else if trust === "Unverified"}
  <div class="badge unverified" role="status">
    <span class="mark" aria-hidden="true">?</span>
    <span class="text">
      <strong>Unverified package</strong>
      <span class="sub">No trusted package signature is available.</span>
    </span>
  </div>
{:else}
  <div class="badge unknown" role="alert">
    <span class="mark" aria-hidden="true">!</span>
    <span class="text">
      <strong>Unknown trust state</strong>
      <span class="sub">Unexpected value: <code>{String(trust)}</code></span>
    </span>
  </div>
{/if}

<style>
  .badge {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    padding: 0.7rem 0.8rem;
    border-radius: var(--radius);
    border: 1px solid transparent;
    line-height: 1.35;
  }
  .mark {
    flex: 0 0 auto;
    min-width: 2rem;
    padding: 0.12rem 0.32rem;
    border-radius: 999px;
    border: 1px solid currentColor;
    text-align: center;
    font-size: 0.68rem;
    font-weight: 800;
    letter-spacing: 0;
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    word-break: break-word;
  }
  .sub {
    font-size: 0.85rem;
    opacity: 0.88;
  }
  code {
    font-size: 0.82rem;
    word-break: break-all;
  }

  .verified {
    background: var(--ok-soft);
    border-color: var(--ok);
    color: var(--ok);
  }
  .new-publisher {
    background: var(--accent-soft);
    border-color: var(--accent);
    color: var(--accent);
  }
  .publisher-changed,
  .unknown {
    background: var(--bad-bg);
    border-color: var(--bad);
    color: var(--bad);
    font-weight: 600;
  }
  .unverified {
    background: var(--warn-soft);
    border-color: var(--warn);
    color: var(--warn);
  }
</style>
