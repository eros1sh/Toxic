//! Toxic CLI — disk şifreleme komut satırı arayüzü.
//!
//! Faz 1 komutları: keyfile hash/new, benchmark.
//! Faz 2'de: create, mount, unmount, change-password.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use toxic_core::{
    kdf::KdfCost,
    keyfile::KeyfileDigest,
    password::Password,
};

// ── CLI tanımı ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "toxic",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Açık kaynak disk şifreleme aracı",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Keyfile işlemleri.
    Keyfile {
        #[command(subcommand)]
        action: KeyfileAction,
    },
    /// KDF maliyet seviyesi kıyaslama testi.
    Benchmark {
        /// Test edilecek maliyet seviyesi (1–64; varsayılan: 16).
        #[arg(short, long, default_value_t = 16)]
        level: u8,
    },
    /// Yeni şifreli volume oluştur (Faz 2'de tam implementasyon).
    Create {
        /// Oluşturulacak volume dosyasının yolu.
        path: PathBuf,
        /// Volume boyutu (örn. 100M, 1G, 500K).
        #[arg(short, long)]
        size: String,
        /// Keyfile(lar) (isteğe bağlı, çoklu kullanılabilir).
        #[arg(short = 'k', long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeyfileAction {
    /// Bir dosyanın BLAKE2b-256 özetini hesaplar.
    Hash {
        /// Özeti hesaplanacak dosya.
        file: PathBuf,
    },
    /// Rastgele bir keyfile oluşturur (64 KiB).
    New {
        /// Oluşturulacak keyfile yolu.
        output: PathBuf,
    },
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keyfile { action } => cmd_keyfile(action),
        Commands::Benchmark { level } => cmd_benchmark(level),
        Commands::Create { path, size, keyfiles } => cmd_create(path, size, keyfiles),
    }
}

// ── keyfile hash ──────────────────────────────────────────────────────────────

fn cmd_keyfile(action: KeyfileAction) -> Result<()> {
    match action {
        KeyfileAction::Hash { file } => {
            let data = std::fs::read(&file)
                .with_context(|| format!("Dosya okunamadı: {}", file.display()))?;

            let digest = KeyfileDigest::from_bytes(&data)
                .context("Keyfile geçersiz (boş olamaz)")?;
            println!("{}", hex::encode(digest.as_bytes()));
            Ok(())
        }
        KeyfileAction::New { output } => {
            use rand_core::{OsRng, RngCore};
            let mut buf = vec![0u8; 65_536]; // 64 KiB
            OsRng.fill_bytes(&mut buf);
            std::fs::write(&output, &buf)
                .with_context(|| format!("Keyfile yazılamadı: {}", output.display()))?;
            println!("Keyfile oluşturuldu: {} (64 KiB)", output.display());
            Ok(())
        }
    }
}

// ── benchmark ─────────────────────────────────────────────────────────────────

fn cmd_benchmark(level: u8) -> Result<()> {
    let cost = KdfCost::new(level).context("Geçersiz maliyet seviyesi (1–64 arası olmalı).")?;

    let password = rpassword::prompt_password("Kıyaslama parolası: ")
        .context("Parola okunamadı")?;
    let pw = Password::new(password.as_bytes(), false)
        .context("Parola geçersiz")?;

    // Sahte tuz (kıyaslama için sabit).
    let salt = [0x42u8; 32];

    let start = std::time::Instant::now();
    let mut out = [0u8; 32];
    toxic_core::kdf::derive_header_key(pw.as_bytes(), &salt, cost, &mut out)
        .context("KDF başarısız")?;
    let elapsed = start.elapsed();

    println!("Seviye    : {level}");
    println!("Bellek    : {} KiB", cost.m_cost_kib());
    println!("Yineleme  : {}", cost.t_cost());
    println!("Süre      : {:.2} s", elapsed.as_secs_f64());
    Ok(())
}

// ── create (stub) ─────────────────────────────────────────────────────────────

fn cmd_create(path: PathBuf, size: String, keyfiles: Vec<PathBuf>) -> Result<()> {
    // Faz 2'de tam implementasyon yapılacak.
    // Şimdilik parametreleri doğrula ve kullanıcıya bilgi ver.
    let bytes = parse_size(&size).context("Geçersiz boyut formatı (örn. 100M, 1G)")?;

    println!("Volume oluşturma: {}", path.display());
    println!("Boyut   : {} bayt ({size})", bytes);
    println!("Keyfile : {}", if keyfiles.is_empty() { "yok".into() } else { keyfiles.len().to_string() });
    println!();
    println!("Uyarı: Bu komut henüz Faz 2'de implemente edilecek.");
    println!("       Şu an yalnızca parametreler doğrulandı.");
    Ok(())
}

/// "100M", "1G", "500K" gibi boyut ifadelerini bayta çevirir.
fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() { bail!("Boş boyut"); }

    let (num_part, unit) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        s.split_at(s.len() - 1)
    } else {
        (s, "")
    };

    let n: u64 = num_part.parse().context("Sayısal değer geçersiz")?;

    let multiplier = match unit.to_uppercase().as_str() {
        ""  | "B" => 1u64,
        "K"       => 1024,
        "M"       => 1024 * 1024,
        "G"       => 1024 * 1024 * 1024,
        other     => bail!("Bilinmeyen boyut birimi: {other}"),
    };

    Ok(n.checked_mul(multiplier).context("Boyut overflow")?)
}
