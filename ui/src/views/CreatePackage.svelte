<script>
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { convertFileSrc } from "@tauri-apps/api/core";
  import { buildPackage, generateKeypair, inspectAppSource } from "../lib/api.js";

  let appDir = $state("");
  let entry = $state("");
  let id = $state("");
  let name = $state("");
  let publisher = $state("");
  let version = $state("1.0.0");
  let homepage = $state("");
  let shortcutName = $state("");
  let network = $state(true);
  let iconPath = $state("");

  let secretKeyPath = $state("");
  let publicKey = $state("");
  let password = $state("");
  let generatedKey = $state("");

  let outputPath = $state("");
  let busy = $state(false);
  let error = $state("");
  let success = $state("");
  let detected = $state(0);
  let inspecting = $state(false);

  function baseName(path) {
    return path.replace(/\\/g, "/").split("/").pop() || "";
  }

  function relativeToAppDir(path) {
    if (!appDir) return baseName(path);
    const normalizedRoot = appDir.replace(/\\/g, "/").replace(/\/+$/, "");
    const normalizedPath = path.replace(/\\/g, "/");
    if (normalizedPath.toLowerCase().startsWith(`${normalizedRoot.toLowerCase()}/`)) {
      return normalizedPath.slice(normalizedRoot.length + 1);
    }
    return baseName(path);
  }

  function guessBundleId(label) {
    const slug = label
      .toLowerCase()
      .replace(/\.[^.]+$/, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return slug ? `com.example.${slug}` : "";
  }

  async function pickAppDir() {
    const sel = await open({ directory: true, multiple: false });
    if (typeof sel === "string") {
      appDir = sel;
      await autofillFrom(sel);
    }
  }

  async function pickAppExe() {
    const sel = await open({
      multiple: false,
      filters: [{ name: "Windows executable", extensions: ["exe"] }],
    });
    if (typeof sel === "string") {
      appDir = sel;
      await autofillFrom(sel);
    }
  }

  // Inspect the chosen app folder/exe and pre-fill the form from the app's own
  // version info (ProductName / CompanyName / version). Best-effort.
  async function autofillFrom(path) {
    error = "";
    inspecting = true;
    detected = 0;
    try {
      const info = await inspectAppSource(path);
      detected = info.fileCount || 0;
      if (info.suggestedEntry) entry = info.suggestedEntry;
      const label = info.name || baseName(entry).replace(/\.exe$/i, "");
      if (label) {
        if (!name) name = label;
        if (!shortcutName) shortcutName = label;
        if (!id) id = guessBundleId(label);
      }
      if (info.publisher && !publisher) publisher = info.publisher;
      if (info.version && (!version || version === "1.0.0")) version = info.version;
    } catch (e) {
      // Fall back to a filename-based guess.
      const label = baseName(path).replace(/\.exe$/i, "");
      if (path.toLowerCase().endsWith(".exe")) entry = baseName(path);
      if (label && !name) name = label;
      if (label && !shortcutName) shortcutName = label;
      if (label && !id) id = guessBundleId(label);
    } finally {
      inspecting = false;
    }
  }

  async function pickIcon() {
    const sel = await open({
      multiple: false,
      filters: [{ name: "PNG app icon", extensions: ["png"] }],
    });
    if (typeof sel === "string") iconPath = sel;
  }

  async function pickEntry() {
    const sel = await open({
      multiple: false,
      defaultPath: appDir || undefined,
      filters: [{ name: "Windows executable", extensions: ["exe"] }],
    });
    if (typeof sel === "string") {
      entry = relativeToAppDir(sel);
      const label = baseName(sel).replace(/\.exe$/i, "");
      if (!name) name = label;
      if (!shortcutName) shortcutName = label;
      if (!id) id = guessBundleId(label);
    }
  }

  async function pickSecretKey() {
    const sel = await open({ multiple: false, filters: [{ name: "minisign secret key", extensions: ["key"] }] });
    if (typeof sel === "string") secretKeyPath = sel;
  }

  async function pickPublicKey() {
    const sel = await open({ multiple: false, filters: [{ name: "minisign public key", extensions: ["pub"] }] });
    if (typeof sel === "string") publicKey = sel;
  }

  async function pickOutput() {
    const def = `${id || "app"}-${version || "1.0.0"}.oip`;
    const sel = await save({ defaultPath: def, filters: [{ name: "OpenInstall package", extensions: ["oip"] }] });
    if (typeof sel === "string") outputPath = sel;
  }

  async function genKey() {
    error = "";
    const sel = await save({ defaultPath: "publisher.key", filters: [{ name: "minisign secret key", extensions: ["key"] }] });
    if (typeof sel !== "string") return;
    const prefix = sel.replace(/\.(key|pub)$/i, "");
    try {
      const res = await generateKeypair(prefix, password || null);
      secretKeyPath = res.secretKeyPath;
      publicKey = res.publicKeyPath;
      generatedKey = res.publicKey;
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    }
  }

  const canBuild = $derived(
    !!appDir &&
      !!entry.trim() &&
      !!id.trim() &&
      !!name.trim() &&
      !!publisher.trim() &&
      !!version.trim() &&
      !!outputPath &&
      !!secretKeyPath &&
      !!publicKey,
  );

  const iconPreview = $derived(iconPath ? convertFileSrc(iconPath) : "");

  const progress = $derived(
    [
      !!appDir && !!entry.trim(),
      !!id.trim() && !!name.trim() && !!publisher.trim() && !!version.trim(),
      !!secretKeyPath && !!publicKey,
      !!outputPath,
    ].filter(Boolean).length,
  );

  async function build() {
    if (!canBuild) return;
    busy = true;
    error = "";
    success = "";
    try {
      const spec = {
        appDir,
        outputPath,
        id: id.trim(),
        name: name.trim(),
        publisher: publisher.trim(),
        version: version.trim(),
        homepage: homepage.trim(),
        entry: entry.trim().replace(/\\/g, "/"),
        shortcutName: shortcutName.trim() || name.trim(),
        network,
        iconPath,
        publicKey,
        secretKeyPath,
        password: password ? password : null,
      };
      const res = await buildPackage(spec);
      success = `Built signed v1 package: ${res.outputPath} (${res.size} bytes)`;
    } catch (e) {
      error = typeof e === "string" ? e : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="create">
  <section class="hero">
    <div>
      <p class="eyebrow">Publisher tools</p>
      <h1>Create</h1>
      <p>Build a signed OpenInstall v1 package from an app folder or a single .exe.</p>
    </div>
    <button class="primary" onclick={build} disabled={!canBuild || busy}>
      {busy ? "Building..." : "Build package"}
    </button>
  </section>

  <div class="layout">
    <div class="form-stack">
      <section class="group">
        <div class="group-head">
          <span class="step">1</span>
          <div>
            <h2>App files</h2>
            <p>Choose an app folder, or package a single executable directly.</p>
          </div>
        </div>
        <div class="field">
          <span class="lab">App source</span>
          <div class="pick three">
            <input type="text" readonly value={appDir} placeholder="app folder or BaarReader.exe" />
            <button type="button" onclick={pickAppDir}>Folder</button>
            <button type="button" onclick={pickAppExe}>.exe</button>
          </div>
          {#if inspecting}
            <p class="hint muted">Reading app info…</p>
          {:else if appDir}
            <p class="hint muted">
              {detected ? `${detected} file${detected === 1 ? "" : "s"} detected` : "Ready"} · name,
              publisher and version auto-filled from the app where available — edit anything below.
            </p>
          {/if}
        </div>
        <div class="field">
          <span class="lab">Entry executable</span>
          <div class="pick">
            <input type="text" bind:value={entry} placeholder="BaarReader.exe" />
            <button type="button" onclick={pickEntry}>Choose</button>
          </div>
        </div>
        <div class="field">
          <span class="lab">App icon (.png)</span>
          <div class="pick">
            <input type="text" readonly value={iconPath} placeholder="assets/icon.png" />
            <button type="button" onclick={pickIcon}>Choose</button>
          </div>
        </div>
      </section>

      <section class="group">
        <div class="group-head">
          <span class="step">2</span>
          <div>
            <h2>App Store metadata</h2>
            <p>This is what users see before they install.</p>
          </div>
        </div>
        <div class="two">
          <label>App id
            <input type="text" bind:value={id} placeholder="com.example.coolapp" />
          </label>
          <label>Version
            <input type="text" bind:value={version} placeholder="1.0.0" />
          </label>
        </div>
        <div class="two">
          <label>Name
            <input type="text" bind:value={name} placeholder="CoolApp" />
          </label>
          <label>Publisher
            <input type="text" bind:value={publisher} placeholder="Example Dev" />
          </label>
        </div>
        <div class="two">
          <label>Publisher site
            <input type="text" bind:value={homepage} placeholder="https://coolapp.dev" />
          </label>
          <label>Shortcut name
            <input type="text" bind:value={shortcutName} placeholder={name || "CoolApp"} />
          </label>
        </div>
        <label class="check">
          <input type="checkbox" bind:checked={network} />
          <span>Declare network access</span>
        </label>
      </section>

      <section class="group">
        <div class="group-head">
          <span class="step">3</span>
          <div>
            <h2>Publisher signature</h2>
            <p>Every v1 package created here is signed with your publisher key.</p>
          </div>
        </div>
        <div class="field">
          <span class="lab">Secret key (.key)</span>
          <div class="pick three">
            <input type="text" readonly value={secretKeyPath} placeholder="publisher.key" />
            <button type="button" onclick={pickSecretKey}>Choose</button>
            <button type="button" onclick={genKey}>Generate</button>
          </div>
        </div>
        <div class="field">
          <span class="lab">Public key (.pub or RW...)</span>
          <div class="pick">
            <input type="text" bind:value={publicKey} placeholder="publisher.pub" />
            <button type="button" onclick={pickPublicKey}>Choose</button>
          </div>
        </div>
        <label>Key password
          <input type="password" bind:value={password} placeholder="leave blank if none" />
        </label>
        {#if generatedKey}
          <p class="note">Generated key: <code>{generatedKey}</code></p>
        {/if}
      </section>

      <section class="group">
        <div class="group-head">
          <span class="step">4</span>
          <div>
            <h2>Output</h2>
            <p>The package can be published directly in an OpenInstall repo.</p>
          </div>
        </div>
        <div class="field">
          <span class="lab">Save .oip to</span>
          <div class="pick">
            <input type="text" readonly value={outputPath} placeholder="app-1.0.0.oip" />
            <button type="button" onclick={pickOutput}>Choose</button>
          </div>
        </div>
      </section>

      {#if error}<p class="error" role="alert">{error}</p>{/if}
      {#if success}<p class="ok" role="status">{success}</p>{/if}
    </div>

    <aside class="summary">
      <div class="app-preview">
        <div class="app-icon">
          {#if iconPreview}
            <img src={iconPreview} alt="" />
          {:else}
            <span>{(name || "O").slice(0, 1).toUpperCase()}</span>
          {/if}
        </div>
        <div class="app-name">{name || "New App"}</div>
        <div class="app-publisher">{publisher || "Publisher"}</div>
        <button type="button" disabled>Get</button>
      </div>

      <div class="checklist">
        <div class:done={progress >= 1}><span></span> App files</div>
        <div class:done={progress >= 2}><span></span> Metadata</div>
        <div class:done={progress >= 3}><span></span> Signature</div>
        <div class:done={progress >= 4}><span></span> Output</div>
      </div>

      <button class="primary build" onclick={build} disabled={!canBuild || busy}>
        {busy ? "Building..." : "Build package"}
      </button>
    </aside>
  </div>
</div>

<style>
  .create {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .hero {
    padding: 1.5rem 1.6rem;
    border-radius: var(--radius);
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--fg);
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
  }

  .eyebrow {
    margin: 0 0 0.35rem;
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--accent);
  }

  .hero h1 {
    margin: 0;
    font-size: clamp(1.7rem, 3vw, 2.3rem);
    line-height: 1.05;
    letter-spacing: -0.02em;
  }

  .hero p {
    margin: 0.4rem 0 0;
    max-width: 520px;
    font-size: 0.95rem;
    color: var(--muted);
  }

  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: 1.2rem;
    align-items: start;
  }

  .form-stack {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }

  .group,
  .summary {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 22px;
    box-shadow: var(--shadow-soft), var(--highlight);
    backdrop-filter: blur(22px) saturate(160%);
  }

  .group {
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
  }

  .group-head {
    display: grid;
    grid-template-columns: 34px minmax(0, 1fr);
    gap: 0.75rem;
    align-items: start;
  }

  .step {
    width: 34px;
    height: 34px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
  }

  h2,
  p {
    margin: 0;
  }

  h2 {
    font-size: 1.05rem;
  }

  .group-head p {
    color: var(--muted);
    margin-top: 0.15rem;
  }

  label,
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.32rem;
    color: var(--fg);
    font-weight: 600;
  }

  .lab {
    color: var(--fg);
    font-size: 0.9rem;
    font-weight: 600;
  }

  .hint {
    margin: 0.1rem 0 0;
    font-size: 0.82rem;
    line-height: 1.35;
  }

  .two {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
  }

  .pick {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.5rem;
  }

  .pick.three {
    grid-template-columns: minmax(0, 1fr) auto auto;
  }

  .check {
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
  }

  .check input {
    width: auto;
  }

  .note,
  .ok {
    border-radius: 14px;
    padding: 0.75rem 0.85rem;
    margin: 0;
    word-break: break-all;
  }

  .note {
    background: var(--surface-2);
    color: var(--muted);
  }

  .ok {
    color: var(--ok);
    border: 1px solid rgba(36, 138, 61, 0.18);
    background: var(--ok-soft);
  }

  .summary {
    position: sticky;
    top: 1.2rem;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .app-preview {
    min-height: 250px;
    border-radius: var(--radius);
    background: var(--surface-2);
    border: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 1.2rem;
  }

  .app-icon {
    width: 92px;
    height: 92px;
    border-radius: 20px;
    background: var(--surface-3);
    border: 1px solid var(--border);
    color: var(--muted);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2.4rem;
    font-weight: 700;
    overflow: hidden;
  }

  .app-icon img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .app-icon span {
    display: inline-flex;
  }

  .app-name {
    margin-top: 0.9rem;
    font-size: 1.18rem;
    font-weight: 800;
  }

  .app-publisher {
    color: var(--muted);
    margin: 0.1rem 0 0.85rem;
  }

  .checklist {
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }

  .checklist div {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    color: var(--muted);
  }

  .checklist span {
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: var(--surface-3);
  }

  .checklist .done {
    color: var(--fg);
    font-weight: 650;
  }

  .checklist .done span {
    background: var(--ok);
  }

  .build {
    width: 100%;
  }

  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }

    .summary {
      position: static;
      order: -1;
    }
  }

  @media (max-width: 680px) {
    .hero {
      align-items: flex-start;
      flex-direction: column;
    }

    .two,
    .pick,
    .pick.three {
      grid-template-columns: 1fr;
    }
  }
</style>
