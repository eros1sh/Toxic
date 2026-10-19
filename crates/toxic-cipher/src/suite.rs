//! Algoritma çevikliği (F-013): CipherSuite enum ve SectorCipher trait.

use crate::{AesXtsCipher, CipherError, SerpentXtsCipher, TwofishXtsCipher, XTS_KEY_SIZE};

/// Desteklenen şifre paketleri.
///
/// Disk üzerinde 1 bayt olarak saklanır; gelecekte cascade seçenekleri eklenebilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-256-XTS (varsayılan, donanım hızlandırmalı).
    Aes256Xts = 1,
    /// Serpent-256-XTS (bit-sliced, sabit zamanlı).
    Serpent256Xts = 2,
    /// Twofish-256-XTS (tablo tabanlı).
    Twofish256Xts = 3,
    // Faz 7: AES+Twofish+Serpent cascade = 4
}

impl CipherSuite {
    /// Ham bayttan dönüştürür; bilinmeyen değer için `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(CipherSuite::Aes256Xts),
            2 => Some(CipherSuite::Serpent256Xts),
            3 => Some(CipherSuite::Twofish256Xts),
            _ => None,
        }
    }

    /// `SectorCipher` implementasyonu döner.
    pub fn build(&self, key: &[u8; XTS_KEY_SIZE]) -> Result<AnyCipher, CipherError> {
        match self {
            CipherSuite::Aes256Xts     => Ok(AnyCipher::Aes(AesXtsCipher::new(key)?)),
            CipherSuite::Serpent256Xts => Ok(AnyCipher::Serpent(SerpentXtsCipher::new(key)?)),
            CipherSuite::Twofish256Xts => Ok(AnyCipher::Twofish(TwofishXtsCipher::new(key)?)),
        }
    }
}

/// Sektör düzeyi şifreleme/deşifreleme arayüzü.
pub trait SectorCipher {
    /// Bir sektörü yerinde şifreler.
    fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError>;
    /// Bir sektörü yerinde deşifreler.
    fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError>;
}

/// Heap tahsisi olmadan çalışan enum dispatch (no_alloc uyumu).
#[derive(Debug)]
pub enum AnyCipher {
    Aes(AesXtsCipher),
    Serpent(SerpentXtsCipher),
    Twofish(TwofishXtsCipher),
}

impl SectorCipher for AnyCipher {
    fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        match self {
            AnyCipher::Aes(c)     => c.encrypt_sector(sector, sector_index),
            AnyCipher::Serpent(c) => c.encrypt_sector(sector, sector_index),
            AnyCipher::Twofish(c) => c.encrypt_sector(sector, sector_index),
        }
    }

    fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        match self {
            AnyCipher::Aes(c)     => c.decrypt_sector(sector, sector_index),
            AnyCipher::Serpent(c) => c.decrypt_sector(sector, sector_index),
            AnyCipher::Twofish(c) => c.decrypt_sector(sector, sector_index),
        }
    }
}
