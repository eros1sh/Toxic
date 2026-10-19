//! Toxic disk şifreleme çekirdeği.
//!
//! Bu crate `docs/spec/header-format.md` belgesinin referans implementasyonudur. UEFI bootloader,
//! servis ve CLI aynı kodu kullanır; bu yüzden crate `no_std` + `alloc` ile derlenebilir.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
pub mod header;
pub mod kdf;
pub mod keyfile;
pub mod layout;
pub mod password;
pub mod xts;

pub use error::{Error, Result};
pub use header::{Flags, MasterKey, NewVolumeParams, SectorSize, VolumeHeader};
pub use kdf::KdfCost;
pub use keyfile::{KeyfileDigest, KeyfileSecret};
pub use password::Password;
pub use xts::DataCipher;

// ── ADR-003 Çok-Slot Format Sabitleri ─────────────────────────────────────────

/// Bir header slotunun bayt cinsinden boyutu: 4 KiB (ADR-003 §2).
pub const SLOT_SIZE: usize = 4_096;
/// Header bölgesindeki slot sayisi: 8 (ADR-003 §2).
pub const SLOT_COUNT: usize = 8;
/// Argon2id paylaşılan bölge tuzu uzunluğu (ADR-003 §2).
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce uzunluğu (ADR-003 §3).
pub const NONCE_LEN: usize = 24;
/// ML-KEM-1024 kapsüllü anahtar boyutu (RFC taslak değeri; Faz 10).
pub const KEM_CT_LEN: usize = 1_600;
/// Sarılmış master key uzunluğu bir slot içinde: 2 × 32 bayt XTS alt-anahtarı + 32 bayt MAC = 96 bayt.
pub const WRAPPED_KEY_LEN: usize = 96;
/// AEAD (Poly1305) etiket uzunluğu (ADR-003 §3).
pub const TAG_LEN: usize = 16;
/// Slot başlık AEAD ilişkili verisi (ADR-003 §3).
pub const HEADER_AAD: &[u8] = b"toxic-header-v1";
/// Metadata bloğu AEAD ilişkili verisi (ADR-003 §5).
pub const META_AAD: &[u8] = b"toxic-meta-v1";
/// Bu implementasyonun okuyabileceği en yüksek format sürümü (ADR-003 §10).
pub const READER_VERSION: u16 = 1;
/// Bu implementasyonun yazdığı format sürümü (ADR-003 §10).
pub const FORMAT_VERSION: u16 = 1;
/// Şifreli header gövdesinin uzunluğu (slot içindeki şifrelenmiş payload); 512 bayt (§6).
pub const BODY_LEN: usize = 512;
