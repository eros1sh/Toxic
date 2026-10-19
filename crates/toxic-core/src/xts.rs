//! XTS-AES-256 veri şifrelemesi (IEEE 1619-2007) — toxic-cipher üzerinden sarıcı.
//!
//! `DataCipher` türü veri sektörlerini şifreleme ve deşifreleme işlemlerini sarar.
//! Gerçek implementasyon `toxic-cipher::AesXtsCipher` içindedir.

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use zeroize::ZeroizeOnDrop;

use crate::{Error, Result};

/// AES-XTS anahtar boyutu: 2 x 256 bit = 64 bayt.
pub const XTS_KEY_SIZE: usize = 64;

/// Veri şifreleme cihazı; AES-256-XTS sarar.
#[derive(ZeroizeOnDrop)]
pub struct DataCipher {
    key_material: [u8; XTS_KEY_SIZE],
}

impl DataCipher {
    /// 64 baytlık ham XTS anahtarından yeni bir `DataCipher` oluşturur.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != XTS_KEY_SIZE {
            return Err(Error::BufferSize);
        }
        let mut key_material = [0u8; XTS_KEY_SIZE];
        key_material.copy_from_slice(key);
        Ok(DataCipher { key_material })
    }

    /// Bir sektörü yerinde şifreler.
    pub fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<()> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(Error::BufferSize);
        }
        let k1 = Aes256::new_from_slice(&self.key_material[..32]).map_err(|_| Error::Aead)?;
        let k2 = Aes256::new_from_slice(&self.key_material[32..]).map_err(|_| Error::Aead)?;
        xts_encrypt(sector, sector_index, &k1, &k2);
        Ok(())
    }

    /// Bir sektörü yerinde deşifreler.
    pub fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<()> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(Error::BufferSize);
        }
        let k1 = Aes256::new_from_slice(&self.key_material[..32]).map_err(|_| Error::Aead)?;
        let k2 = Aes256::new_from_slice(&self.key_material[32..]).map_err(|_| Error::Aead)?;
        xts_decrypt(sector, sector_index, &k1, &k2);
        Ok(())
    }
}

impl core::fmt::Debug for DataCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DataCipher([redacted])")
    }
}

// ── Yerleşik XTS (aes cipher 0.4.x ile) ─────────────────────────────────────

fn xts_encrypt(data: &mut [u8], sector_idx: u64, k1: &Aes256, k2: &Aes256) {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_idx.to_le_bytes());
    {
        let blk = aes::Block::from_mut_slice(&mut tweak);
        k2.encrypt_block(blk);
    }
    for block in data.chunks_exact_mut(16) {
        let blk: &mut [u8; 16] = block.try_into().unwrap();
        xor16(blk, &tweak);
        k1.encrypt_block(aes::Block::from_mut_slice(blk));
        xor16(blk, &tweak);
        gf_mul_alpha(&mut tweak);
    }
}

fn xts_decrypt(data: &mut [u8], sector_idx: u64, k1: &Aes256, k2: &Aes256) {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_idx.to_le_bytes());
    {
        let blk = aes::Block::from_mut_slice(&mut tweak);
        k2.encrypt_block(blk);
    }
    for block in data.chunks_exact_mut(16) {
        let blk: &mut [u8; 16] = block.try_into().unwrap();
        xor16(blk, &tweak);
        k1.decrypt_block(aes::Block::from_mut_slice(blk));
        xor16(blk, &tweak);
        gf_mul_alpha(&mut tweak);
    }
}

#[inline(always)]
fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 { a[i] ^= b[i]; }
}

#[inline(always)]
fn gf_mul_alpha(t: &mut [u8; 16]) {
    let carry = (t[15] >> 7) & 1;
    for i in (1..16).rev() { t[i] = (t[i] << 1) | (t[i - 1] >> 7); }
    t[0] <<= 1;
    if carry != 0 { t[0] ^= 0x87; }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() { *b = i as u8; }
        k
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = DataCipher::new(&make_key()).unwrap();
        let mut sector = [0x42u8; 512];
        let original = sector;
        cipher.encrypt_sector(&mut sector, 42).unwrap();
        assert_ne!(sector, original);
        cipher.decrypt_sector(&mut sector, 42).unwrap();
        assert_eq!(sector, original);
    }

    #[test]
    fn different_sector_index_different_ciphertext() {
        let cipher = DataCipher::new(&make_key()).unwrap();
        let plaintext = [0x55u8; 512];
        let mut s1 = plaintext; let mut s2 = plaintext;
        cipher.encrypt_sector(&mut s1, 0).unwrap();
        cipher.encrypt_sector(&mut s2, 1).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn wrong_key_size_rejected() {
        assert_eq!(DataCipher::new(&[0u8; 32]).unwrap_err(), Error::BufferSize);
        assert!(DataCipher::new(&[0u8; 64]).is_ok());
    }

    #[test]
    fn empty_sector_rejected() {
        let cipher = DataCipher::new(&make_key()).unwrap();
        assert_eq!(cipher.encrypt_sector(&mut [], 0).unwrap_err(), Error::BufferSize);
    }
}
