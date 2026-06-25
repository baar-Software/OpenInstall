//! `oip-cli` — developer CLI to build and sign native OpenInstall (`.oip`)
//! packages. It produces the EXACT same native `manifest.json` + `files/`
//! packages the GUI's Create view produces (both go through `oip-pack`), so a
//! CLI-built package installs through the OpenInstall client identically.
//!
//!   oip-cli keygen --out <prefix> [--password <pw>]
//!   oip-cli build  --app <folder|exe> --out <app.oip>
//!                  --id <id> --name <n> --publisher <p> --version <v>
//!                  --secret-key <key.key> --public-key <key.pub | RW...>
//!                  [--entry <rel.exe>] [--homepage <url>] [--shortcut <name>]
//!                  [--icon <png>] [--no-network] [--password <pw>]
//!   oip-cli verify --package <app.oip>

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "oip-cli", version, about = "Build and sign native OpenInstall (.oip) packages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a minisign keypair (<prefix>.key + <prefix>.pub).
    Keygen(KeygenArgs),
    /// Build + sign a native .oip from an app folder (or a single .exe).
    Build(Box<BuildArgs>),
    /// Verify a .oip the way the OpenInstall client would.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct KeygenArgs {
    /// Output key file prefix; writes <prefix>.key and <prefix>.pub.
    #[arg(long)]
    out: String,
    /// Optional password to encrypt the secret key.
    #[arg(long)]
    password: Option<String>,
    /// Overwrite existing key files.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct BuildArgs {
    /// App folder (or a single .exe) to package.
    #[arg(long)]
    app: PathBuf,
    /// Output .oip path.
    #[arg(long)]
    out: PathBuf,
    /// Reverse-DNS app id, e.g. com.example.coolapp.
    #[arg(long)]
    id: String,
    /// Human-facing app name.
    #[arg(long)]
    name: String,
    /// Human-facing publisher name.
    #[arg(long)]
    publisher: String,
    /// App version, e.g. 1.0.0.
    #[arg(long)]
    version: String,
    /// Minisign secret key file (native packages are always signed).
    #[arg(long)]
    secret_key: PathBuf,
    /// Publisher public key: a path to a .pub file or a bare RW... base64.
    #[arg(long)]
    public_key: String,
    /// Entry-point executable, relative to --app. Inferred (first .exe) if omitted.
    #[arg(long)]
    entry: Option<String>,
    /// Publisher website (optional).
    #[arg(long)]
    homepage: Option<String>,
    /// Start Menu shortcut name (defaults to --name).
    #[arg(long)]
    shortcut: Option<String>,
    /// PNG icon to embed at assets/icon.png (optional).
    #[arg(long)]
    icon: Option<String>,
    /// Disable the network permission (it is on by default, matching the GUI).
    #[arg(long)]
    no_network: bool,
    /// Password if the secret key is encrypted.
    #[arg(long)]
    password: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long)]
    package: PathBuf,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => keygen(a),
        Cmd::Build(a) => build(*a),
        Cmd::Verify(a) => verify(a),
    }
}

fn keygen(a: KeygenArgs) -> Result<()> {
    let sk_path = format!("{}.key", a.out);
    let pk_path = format!("{}.pub", a.out);
    if !a.force {
        for p in [&sk_path, &pk_path] {
            if Path::new(p).exists() {
                bail!("{p} already exists (use --force to overwrite)");
            }
        }
    }

    let kp = oip_pack::generate_keypair(a.password.clone())?;
    std::fs::write(&sk_path, &kp.secret_key_box).with_context(|| format!("writing {sk_path}"))?;
    std::fs::write(&pk_path, &kp.public_key_box).with_context(|| format!("writing {pk_path}"))?;

    println!("Wrote secret key: {sk_path}");
    println!("Wrote public key: {pk_path}");
    println!("Public key (RW): {}", kp.public_key_b64);
    println!();
    println!("Build a signed package with:");
    println!("  oip-cli build --app <folder> --out app.oip --id com.example.app \\");
    println!("    --name \"App\" --publisher \"You\" --version 1.0.0 \\");
    println!("    --secret-key {sk_path} --public-key {pk_path}");
    if !kp.encrypted {
        println!();
        println!("NOTE: this secret key is UNENCRYPTED. Keep it secret; prefer --password for human-held keys.");
    }
    Ok(())
}

fn build(a: BuildArgs) -> Result<()> {
    let public_key_text = read_pubkey_arg(&a.public_key)?;
    let sk_text = std::fs::read_to_string(&a.secret_key)
        .with_context(|| format!("reading secret key {}", a.secret_key.display()))?;

    // Same collection + native build the GUI uses → byte-identical packages.
    let icon = a.icon.as_deref().map(Path::new);
    let (files, inferred_entry) = oip_pack::collect_app_files(&a.app, Some(&a.out), icon)?;

    let entry = match a.entry.as_deref().map(str::trim) {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => inferred_entry,
    };
    if entry.is_empty() {
        bail!(
            "no entry .exe found in {}; pass --entry <relative path>",
            a.app.display()
        );
    }

    let meta = oip_pack::NativeManifestMeta {
        id: a.id,
        name: a.name,
        version: a.version,
        publisher_name: a.publisher,
        publisher_website: a.homepage.unwrap_or_default(),
        entry,
        network: !a.no_network,
        shortcut_name: a.shortcut.unwrap_or_default(),
    };
    let password = a.password.filter(|p| !p.is_empty());
    let oip =
        oip_pack::build_native_oip_bytes(&meta, &files, &public_key_text, &sk_text, password)?;
    std::fs::write(&a.out, &oip).with_context(|| format!("writing {}", a.out.display()))?;

    println!(
        "Built signed native package {} ({} bytes, {} files).",
        a.out.display(),
        oip.len(),
        files.len()
    );
    Ok(())
}

fn verify(a: VerifyArgs) -> Result<()> {
    let oip =
        std::fs::read(&a.package).with_context(|| format!("reading {}", a.package.display()))?;
    let report = oip_pack::verify_oip_auto(&oip)?;

    println!("file hashes: OK");
    if report.signed {
        println!(
            "signature: OK (key {})",
            report.key_fingerprint.as_deref().unwrap_or("?")
        );
    } else {
        println!("signature: NONE — package is UNSIGNED");
    }
    println!("trust (no local pin): {:?}", report.trust);
    println!("{} ({}) — {}", report.name, report.version, report.id);
    Ok(())
}

/// A `--public-key` argument is either a path to a `.pub` file or a bare RW key.
fn read_pubkey_arg(arg: &str) -> Result<String> {
    let p = Path::new(arg);
    if p.exists() {
        std::fs::read_to_string(p).with_context(|| format!("reading {arg}"))
    } else {
        Ok(arg.to_string())
    }
}
