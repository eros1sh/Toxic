//! Anahtar türetme: Argon2id ile parola + keyfile bileşiminden header anahtarı üretir.
//!
//! ADR-001 ve ADR-003 kapsaminda; tek bir Argon2id türetimi yapılır, sonra 8 slot
//! AEAD denemeleri ucuza gelir.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{Error, Result, SALT_LEN};

/// Alan ayırma etiketi: IKM önüne eklenerek Argon2id domain separation sağlar (ADR-003 §4).
const DOMAIN_LABEL: &[u8] = b"toxic-header-v1\x00";

/// Argon2id maliyet parametreleri.
///
/// Kapsam:
/// - Normal volume'lar: herhangi bir `level` (1-64)
/// - Sistem volume'lari (pre-boot): `level` <= 16 (ToxicBoot bellek kısıtı)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    /// Maliyet seviyesi (1-64). Bellek ve iterasyon sayısını etkiler.
    pub level: u8,
}

impl KdfCost {
    /// Varsayılan maliyet (interaktif kullanım için dengeli).
    pub const DEFAULT: KdfCost = KdfCost { level: 8 };
    /// Maksimum sistem volume maliyeti (ToxicBoot RAM kısıtı).
    pub const MAX_SYSTEM: KdfCost = KdfCost { level: 16 };
    /// Maksimum maliyet seviyesi.
    pub const MAX: KdfCost = KdfCost { level: 64 };

    /// Yeni bir `KdfCost` oluşturur; aralık dışındaysa hata döner.
    pub fn new(level: u8) -> Result<Self> {
        if level == 0 || level > 64 {
            return Err(Error::InvalidCost);
        }
        Ok(KdfCost { level })
    }

    /// Bu maliyet seviyesinin Argon2id bellek parametresini KiB cinsinden döner.
    ///
    /// Formül: `64 * 2^(level-1)` KiB
    /// level=1: 64 KiB, level=8: 8192 KiB (8 MB)
    pub fn m_cost_kib(self) -> u32 {
        let shift = u32::from(self.level.saturating_sub(1));
        // 64 << shift; taşma durumunda u32::MAX'a doyumlama yap.
        64u32.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
    }

    /// Bu maliyet seviyesinin Argon2id iterasyon sayısını döner.
    ///
    /// Formül: `max(1, level / 4)` iterasyon.
    pub fn t_cost(self) -> u32 {
        u32::from(self.level / 4).max(1)
    }
}

/// Header anahtarını Argon2id ile türetir.
///
/// # Parametreler
/// - `ikm`: anahtar materyali (parola + keyfile bileşimi, bkz. `KeyfileSecret`)
/// - `salt`: 32 bayt rastgele tuz (ADR-003: `region_salt`)
/// - `cost`: Argon2id maliyet parametreleri
/// - `out`: türetilen anahtarın yazılacağı tampon (32 bayt)
///
/// # Güvenlik
/// `ikm` ve `out` bellekte `zeroize` ile temizlenmeli; çağıran taraf sorumludur.
/// Bu fonksiyon `out` tamponunu hata durumunda sıfırlar.
pub fn derive_header_key(
    ikm: &[u8],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
    out: &mut [u8; 32],
) -> Result<()> {
    // Domain separation: DOMAIN_LABEL || ikm
    // Bu, farklı bağlamlarda aynı IKM kullanılmasını engeller.
    let labeled_len = DOMAIN_LABEL.len() + ikm.len();
    let mut labeled = Zeroizing::new(alloc::vec![0u8; labeled_len]);
    labeled[..DOMAIN_LABEL.len()].copy_from_slice(DOMAIN_LABEL);
    labeled[DOMAIN_LABEL.len()..].copy_from_slice(ikm);

    let params = Params::new(
        cost.m_cost_kib(),
        cost.t_cost(),
        // Parallelism: tek iş parçacığı (no_std uyumu, bootloader kısıtı).
        1,
        Some(32),
    )
    .map_err(|_| Error::InvalidCost)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2.hash_password_into(&labeled, salt, out).map_err(|_| {
        // Hata durumunda kısmen dolu tamponu sıfırla.
        for b in out.iter_mut() {
            *b = 0;
        }
        Error::Kdf
    })
}

/// `derive_header_key` için Zeroizing sarıcı.
///
/// Dönen `Zeroizing<[u8; 32]>` kapsam dışına çıktığında otomatik sıfırlanır.
pub fn derive_header_key_zeroizing(
    ikm: &[u8],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    derive_header_key(ikm, salt, cost, &mut *key)?;
    Ok(key)
}

// alloc import (no_std uyumu)
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_cost_level_bounds() {
        assert!(KdfCost::new(0).is_err());
        assert!(KdfCost::new(65).is_err());
        assert!(KdfCost::new(1).is_ok());
        assert!(KdfCost::new(64).is_ok());
    }

    #[test]
    fn kdf_cost_m_cost() {
        // level 1: 64 KiB
        assert_eq!(KdfCost::new(1).unwrap().m_cost_kib(), 64);
        // level 8: 64 * 128 = 8192 KiB
        assert_eq!(KdfCost::new(8).unwrap().m_cost_kib(), 8192);
    }

    #[test]
    fn kdf_cost_t_cost() {
        assert_eq!(KdfCost::new(1).unwrap().t_cost(), 1); // max(1, 0) = 1
        assert_eq!(KdfCost::new(4).unwrap().t_cost(), 1);
        assert_eq!(KdfCost::new(8).unwrap().t_cost(), 2);
    }

    #[test]
    fn derive_deterministic() {
        // Aynı girdi => aynı çıktı.
        let salt = [0x55u8; 32];
        let ikm = b"test-password";
        let cost = KdfCost::new(1).unwrap();

        let k1 = derive_header_key_zeroizing(ikm, &salt, cost).unwrap();
        let k2 = derive_header_key_zeroizing(ikm, &salt, cost).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_different_salt() {
        // Farklı tuz => farklı çıktı.
        let salt1 = [0x55u8; 32];
        let salt2 = [0xAAu8; 32];
        let ikm = b"test-password";
        let cost = KdfCost::new(1).unwrap();

        let k1 = derive_header_key_zeroizing(ikm, &salt1, cost).unwrap();
        let k2 = derive_header_key_zeroizing(ikm, &salt2, cost).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_different_password() {
        // Farklı parola => farklı çıktı.
        let salt = [0x11u8; 32];
        let cost = KdfCost::new(1).unwrap();

        let k1 = derive_header_key_zeroizing(b"password1", &salt, cost).unwrap();
        let k2 = derive_header_key_zeroizing(b"password2", &salt, cost).unwrap();
        assert_ne!(*k1, *k2);
    }
}
