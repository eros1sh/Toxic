//! Keyfile isleme: BLAKE2b-256 ile keyfile özeti hesaplar ve parola ile birleştirir.
//!
//! ADR-004: Keyfile'lar `DerivationFactor` kategorisinde. Birden fazla keyfile
//! sıraya göre BLAKE2b-256 ile birikimli olarak özete eklenir.

use alloc::vec::Vec;
// blake2 0.10.x: Blake2b<U32> = 256-bit BLAKE2b çıktısı.
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

/// Maksimum keyfile sayısı.
pub const MAX_KEYFILES: usize = 64;

/// Bir keyfile'ın BLAKE2b-256 özeti (32 bayt).
///
/// Header format spec §5: keyfile özeti IKM'ye dahil edilmeden önce parola ile birleştirilir.
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyfileDigest([u8; 32]);

impl KeyfileDigest {
    /// Ham keyfile içeriğinden özet hesaplar.
    ///
    /// # Hatalar
    /// - `EmptyKeyfile`: keyfile 0 bayt ise.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::EmptyKeyfile);
        }
        let hash = Blake2b::<U32>::digest(data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Ok(KeyfileDigest(arr))
    }

    /// Ham özet baytlarını döner (kopyalanmaz).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for KeyfileDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyfileDigest([redacted])")
    }
}

/// Parola + birden fazla keyfile bileşimi; Argon2id IKM olarak kullanılır.
///
/// Birleşim algoritması (ADR-004 §2):
/// 1. `base = NFC(password)` baytları (bkz. `Password`)
/// 2. Her keyfile için `digest = BLAKE2b256(keyfile_bytes)`
/// 3. `combined = BLAKE2b256(base || digest_1 || digest_2 || ...)`
/// 4. Bu birleştirme sıra bağımlıdır: aynı keyfile'lar farklı sırada farklı IKM üretir.
#[derive(ZeroizeOnDrop)]
pub struct KeyfileSecret(Zeroizing<Vec<u8>>);

impl KeyfileSecret {
    /// Yalnızca parola (keyfile yok).
    pub fn from_password_only(password_bytes: &[u8]) -> Result<Self> {
        if password_bytes.is_empty() {
            return Err(Error::EmptySecret);
        }
        // Keyfile yoksa parola doğrudan IKM olarak kullanılır.
        let mut v = Zeroizing::new(Vec::with_capacity(password_bytes.len()));
        v.extend_from_slice(password_bytes);
        Ok(KeyfileSecret(v))
    }

    /// Parola + keyfile özetleri bileşimi.
    ///
    /// # Parametreler
    /// - `password_bytes`: NFC normalleştirilmiş parola UTF-8 baytları (boş olabilir, ama
    ///    keyfile verilmemişse `EmptySecret` hatası verilir)
    /// - `digests`: sıralı keyfile özetleri (en fazla `MAX_KEYFILES` adet)
    ///
    /// # Hatalar
    /// - `TooManyKeyfiles`: 64'ten fazla keyfile.
    /// - `EmptySecret`: hem parola hem keyfile listesi boş.
    pub fn combine(password_bytes: &[u8], digests: &[KeyfileDigest]) -> Result<Self> {
        if digests.is_empty() {
            return Self::from_password_only(password_bytes);
        }
        if digests.len() > MAX_KEYFILES {
            return Err(Error::TooManyKeyfiles);
        }
        if password_bytes.is_empty() && digests.is_empty() {
            return Err(Error::EmptySecret);
        }

        // BLAKE2b256(password || digest_1 || digest_2 || ...)
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(password_bytes);
        for d in digests {
            hasher.update(d.as_bytes());
        }
        let hash = hasher.finalize();

        let mut v = Zeroizing::new(Vec::with_capacity(32));
        v.extend_from_slice(&hash);
        Ok(KeyfileSecret(v))
    }

    /// Ham IKM baytlarını döner; yalnızca `kdf::derive_header_key` tarafından kullanılmalı.
    pub fn as_ikm(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for KeyfileSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyfileSecret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_keyfile_rejected() {
        assert_eq!(KeyfileDigest::from_bytes(&[]).unwrap_err(), Error::EmptyKeyfile);
    }

    #[test]
    fn too_many_keyfiles() {
        let d = KeyfileDigest::from_bytes(b"test").unwrap();
        let digests: Vec<KeyfileDigest> = (0..65).map(|_| d.clone()).collect();
        assert_eq!(
            KeyfileSecret::combine(b"pw", &digests).unwrap_err(),
            Error::TooManyKeyfiles
        );
    }

    #[test]
    fn empty_secret_rejected() {
        assert_eq!(
            KeyfileSecret::from_password_only(b"").unwrap_err(),
            Error::EmptySecret
        );
    }

    #[test]
    fn password_only_ikm() {
        let s = KeyfileSecret::from_password_only(b"hunter2").unwrap();
        assert_eq!(s.as_ikm(), b"hunter2");
    }

    #[test]
    fn combine_deterministic() {
        let d1 = KeyfileDigest::from_bytes(b"keyfile1").unwrap();
        let d2 = KeyfileDigest::from_bytes(b"keyfile2").unwrap();

        let s1 = KeyfileSecret::combine(b"pw", &[d1.clone(), d2.clone()]).unwrap();
        let s2 = KeyfileSecret::combine(b"pw", &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(s1.as_ikm(), s2.as_ikm());
    }

    #[test]
    fn combine_order_matters() {
        // Farklı sıra => farklı IKM (ADR-004 gereği).
        let d1 = KeyfileDigest::from_bytes(b"keyfile1").unwrap();
        let d2 = KeyfileDigest::from_bytes(b"keyfile2").unwrap();

        let s1 = KeyfileSecret::combine(b"pw", &[d1.clone(), d2.clone()]).unwrap();
        let s2 = KeyfileSecret::combine(b"pw", &[d2.clone(), d1.clone()]).unwrap();
        assert_ne!(s1.as_ikm(), s2.as_ikm());
    }

    #[test]
    fn keyfile_changes_ikm() {
        let d1 = KeyfileDigest::from_bytes(b"file_a").unwrap();
        let d2 = KeyfileDigest::from_bytes(b"file_b").unwrap();

        let s1 = KeyfileSecret::combine(b"pw", &[d1]).unwrap();
        let s2 = KeyfileSecret::combine(b"pw", &[d2]).unwrap();
        assert_ne!(s1.as_ikm(), s2.as_ikm());
    }
}
