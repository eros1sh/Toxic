//! XTS-AES-256 veri şifrelemesi (IEEE 1619-2007).
//!
//! `DataCipher` türü veri sektörlerini şifreleme ve deşifreleme işlemlerini sarar.
//! Tam implementasyon Faz 1 kapsamında tamamlanacak; bu dosya tip tanımı ve arayüzü içerir.

use aes::Aes256;
use aes::cipher::KeyInit;
use xts_mode::Xts128;
use zeroize::ZeroizeOnDrop;

use crate::{Error, Result};

/// AES-XTS anahtar boyutu: 2 x 256 bit = 64 bayt.
pub const XTS_KEY_SIZE: usize = 64;

/// Veri şifreleme cihazı; AES-256-XTS sarar.
///
/// Sektör numarası (tweak) little-endian 128-bit tam sayı olarak XTS'e verilir.
#[derive(ZeroizeOnDrop)]
pub struct DataCipher {
    // Anahtarları güvenli bellekte tutuyoruz; Xts128 Drop'ta sıfırlamıyor,
    // bu yüzden ham anahtarı da saklıyoruz.
    key_material: [u8; XTS_KEY_SIZE],
}

impl DataCipher {
    /// 64 baytlık ham XTS anahtarından yeni bir `DataCipher` oluşturur.
    ///
    /// # Hatalar
    /// - `BufferSize`: `key` tam 64 bayt değilse.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != XTS_KEY_SIZE {
            return Err(Error::BufferSize);
        }
        let mut key_material = [0u8; XTS_KEY_SIZE];
        key_material.copy_from_slice(key);
        Ok(DataCipher { key_material })
    }

    /// Bir sektörü yerinde şifreler.
    ///
    /// # Parametreler
    /// - `sector`: şifreleme tamponu (sektör boyutunda olmalı, tipik 512 veya 4096)
    /// - `sector_index`: XTS tweak (sektör numarası, 0-tabanlı)
    ///
    /// # Hatalar
    /// - `BufferSize`: sektör tampon boyutu 16'nın katı değilse veya boşsa.
    pub fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<()> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(Error::BufferSize);
        }
        let cipher = self.build_cipher()?;
        // Tweak: sektör indeksini 128-bit little-endian'a genişlet.
        let tweak = sector_index as u128;
        // get_tweak_fn: verilen indeksi little-endian 16 bayta dönüştür.
        cipher.encrypt_area(sector, sector.len(), tweak, |idx| idx.to_le_bytes());
        Ok(())
    }

    /// Bir sektörü yerinde deşifreler.
    pub fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<()> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(Error::BufferSize);
        }
        let cipher = self.build_cipher()?;
        let tweak = sector_index as u128;
        cipher.decrypt_area(sector, sector.len(), tweak, |idx| idx.to_le_bytes());
        Ok(())
    }

    /// `Xts128` nesnesini anahtar materyalinden oluşturur.
    fn build_cipher(&self) -> Result<Xts128<Aes256>> {
        let k1 = &self.key_material[..32];
        let k2 = &self.key_material[32..];
        Ok(Xts128::<Aes256>::new(
            Aes256::new_from_slice(k1).map_err(|_| Error::Aead)?,
            Aes256::new_from_slice(k2).map_err(|_| Error::Aead)?,
        ))
    }
}

impl core::fmt::Debug for DataCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DataCipher([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = make_key();
        let cipher = DataCipher::new(&key).unwrap();

        let mut sector = [0x42u8; 512];
        let original = sector;
        let sector_idx = 42u64;

        cipher.encrypt_sector(&mut sector, sector_idx).unwrap();
        // Şifreli veri farklı olmalı.
        assert_ne!(sector, original);

        cipher.decrypt_sector(&mut sector, sector_idx).unwrap();
        // Çözülen veri orijinali ile aynı olmalı.
        assert_eq!(sector, original);
    }

    #[test]
    fn different_sector_index_different_ciphertext() {
        let key = make_key();
        let cipher = DataCipher::new(&key).unwrap();

        let plaintext = [0x55u8; 512];

        let mut s1 = plaintext;
        let mut s2 = plaintext;
        cipher.encrypt_sector(&mut s1, 0).unwrap();
        cipher.encrypt_sector(&mut s2, 1).unwrap();

        assert_ne!(s1, s2);
    }

    #[test]
    fn wrong_key_size_rejected() {
        assert_eq!(DataCipher::new(&[0u8; 32]).unwrap_err(), Error::BufferSize);
        assert_eq!(DataCipher::new(&[0u8; 63]).unwrap_err(), Error::BufferSize);
        assert!(DataCipher::new(&[0u8; 64]).is_ok());
    }

    #[test]
    fn empty_sector_rejected() {
        let key = make_key();
        let cipher = DataCipher::new(&key).unwrap();
        assert_eq!(cipher.encrypt_sector(&mut [], 0).unwrap_err(), Error::BufferSize);
    }
}
