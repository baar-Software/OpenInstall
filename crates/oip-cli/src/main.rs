//! `oip-cli` — developer CLI to build and sign OpenInstall (`.oip`) packages.
//! A thin front-end over `oip-pack` (which both this CLI and the GUI share).
//!
//!   oip-cli keygen --out <prefix> [--password <pw>]
//!   oip-cli build  --payload <Setup.exe> --out <app.oip>
//!                  --id <id> --name <n> --publisher <p> --version <v>
//!                  [--homepage <url>] [--type exe|msi] [--silent-args <args>]
//!                  [--public-key <RW... | path/to/key.pub>]
//!   oip-cli sign   --package <app.oip> --secret-key <prefix.key> [--password <pw>]
//!                  [--public-key <RW... | path/to/key.pub>]
//!   oip-cli verify --package <app.oip>

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "oip-cli", version, about = "Build and sign OpenInstall (.oip) packages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a minisign keypair (<prefix>.key + <prefix>.pub).
    Keygen(KeygenArgs),
    /// Build a .oip from a payload + manifest metadata (hashes computed for you).
    Build(BuildArgs),
    /// Sign the manifest inside a .oip, producing manifest.minisig.
    Sign(SignArgs),
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
    #[arg(long)]
    payload: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    publisher: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    homepage: Option<String>,
    /// Payload type: exe or msi.
    #[arg(long = "type", default_value = "exe")]
    payload_type: String,
    /// Args passed to the installer AFTER the user consents (e.g. "/S").
    #[arg(long)]
    silent_args: Option<String>,
    /// Embed a publisher public key (RW... base64 or a path to a .pub file).
    #[arg(long)]
    public_key: Option<String>,
}

#[derive(Args)]
struct SignArgs {
    #[arg(long)]
    package: PathBuf,
    #[arg(long)]
    secret_key: PathBuf,
    #[arg(long)]
    password: Option<String>,
    /// Embed/override the publisher public key before signing.
    #[arg(long)]
    public_key: Option<String>,
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
        Cmd::Build(a) => build(a),
        Cmd::Sign(a) => sign(a),
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
    println!();
    println!("Add this to manifest.toml under [publisher_key]:");
    println!("  type       = \"minisign\"");
    println!("  public_key = \"{}\"", kp.public_key_b64);
    if !kp.encrypted {
        println!();
        println!("NOTE: this secret key is UNENCRYPTED. Keep it secret; prefer --password for human-held keys.");
    }
    Ok(())
}

fn build(a: BuildArgs) -> Result<()> {
    let payload = std::fs::read(&a.payload)
        .with_context(|| format!("reading payload {}", a.payload.display()))?;
    let file_name = a
        .payload
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("payload path has no file name"))?
        .to_string();

    let public_key_text = match &a.public_key {
        Some(arg) => Some(read_pubkey_arg(arg)?),
        None => None,
    };

    let meta = oip_pack::ManifestMeta {
        id: a.id,
        name: a.name,
        publisher: a.publisher,
        version: a.version,
        homepage: a.homepage.unwrap_or_default(),
        payload_type: a.payload_type,
        silent_args: a.silent_args.unwrap_or_default(),
    };

    let oip = oip_pack::build_oip_bytes(&meta, &payload, &file_name, public_key_text.as_deref())?;
    std::fs::write(&a.out, &oip).with_context(|| format!("writing {}", a.out.display()))?;

    println!("Built {} ({} bytes)", a.out.display(), oip.len());
    if public_key_text.is_some() {
        println!("Embedded a publisher key. Sign it next:");
        println!(
            "  oip-cli sign --package {} --secret-key <prefix>.key",
            a.out.display()
        );
    } else {
        println!("WARNING: no publisher key embedded — this package will be UNVERIFIED.");
    }
    Ok(())
}

fn sign(a: SignArgs) -> Result<()> {
    let oip =
        std::fs::read(&a.package).with_context(|| format!("reading {}", a.package.display()))?;
    let secret_key_text = std::fs::read_to_string(&a.secret_key)
        .with_context(|| format!("reading secret key {}", a.secret_key.display()))?;
    let public_key_text = match &a.public_key {
        Some(arg) => Some(read_pubkey_arg(arg)?),
        None => None,
    };

    let signed = oip_pack::sign_oip_bytes(
        &oip,
        &secret_key_text,
        a.password.clone(),
        public_key_text.as_deref(),
    )?;
    std::fs::write(&a.package, &signed)
        .with_context(|| format!("writing {}", a.package.display()))?;

    println!(
        "Signed {} ✓ (signature verifies against the embedded key)",
        a.package.display()
    );
    Ok(())
}

fn verify(a: VerifyArgs) -> Result<()> {
    let oip =
        std::fs::read(&a.package).with_context(|| format!("reading {}", a.package.display()))?;
    let report = oip_pack::verify_oip_bytes(&oip)?;

    println!("payload hashes: OK (BLAKE3 + SHA-256)");
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
/// Returns the text to hand to `oip-pack` (file contents, or the arg verbatim).
fn read_pubkey_arg(arg: &str) -> Result<String> {
    let p = Path::new(arg);
    if p.exists() {
        std::fs::read_to_string(p).with_context(|| format!("reading {arg}"))
    } else {
        Ok(arg.to_string())
    }
}
