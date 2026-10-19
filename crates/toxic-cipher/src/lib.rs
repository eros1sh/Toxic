//! Toxic veri şifreleme crate'i — no_std, no_alloc.
//!
//! AES-256-XTS, Serpent-256-XTS ve Twofish-256-XTS implementasyonları.
//! IEEE 1619 XTS tweak = mutlak sektör numarası (little-endian 128-bit).
//!
//! # Güvenlik
//! - AES-NI otomatik olarak algılanır (CPU feature flag).
//! - AES-NI yoksa `aes` crate'in fixslice (bit-sliced) yazılım yolu kullanılır (F-164).
//! - Serpent bit-sliced olduğundan sabit zamanlıdır (NESSIE vektörleri).
//! - Twofish tablo tabanlıdır; önbellek yan kanalı olası (düşük tehdit, belgelenir).

#![no_std]
#![forbid(unsafe_code)]

mod aes_xts;
mod raw_xts;
mod serpent_xts;
mod twofish_xts;
pub mod suite;

pub use aes_xts::AesXtsCipher;
pub use serpent_xts::SerpentXtsCipher;
pub use twofish_xts::TwofishXtsCipher;
pub use suite::{CipherSuite, SectorCipher};

/// XTS anahtar boyutu: 2 × 256 bit = 64 bayt.
pub const XTS_KEY_SIZE: usize = 64;
/// Minimum sektör boyutu (XTS için 16'nın katı olmalı).
pub const MIN_SECTOR_SIZE: usize = 512;

/// Sektör şifreleme/deşifreleme hatası.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// Anahtar boyutu 64 bayt değil.
    InvalidKeySize,
    /// Tampon boyutu 16'nın katı değil veya boş.
    InvalidBufferSize,
}
