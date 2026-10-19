//! AES-256-XTS sektör şifreleme (F-001, F-164).
//!
//! AES-NI yoksa `aes` crate'in fixslice (bit-sliced) yazılım yolu otomatik devreye girer.
//! XTS implementasyonu: `raw_xts` modülü (cipher 0.4.x trait bağımsız, closure tabanlı).

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use zeroize::ZeroizeOnDrop;

use crate::{raw_xts, CipherError, SectorCipher, XTS_KEY_SIZE};

/// AES-256-XTS şifre cihazı.
#[derive(ZeroizeOnDrop)]
pub struct AesXtsCipher {
    key: [u8; XTS_KEY_SIZE],
}

impl AesXtsCipher {
    /// 64-baytlık ham XTS anahtarından oluşturur.
    pub fn new(key: &[u8; XTS_KEY_SIZE]) -> Result<Self, CipherError> {
        Ok(AesXtsCipher { key: *key })
    }

    fn enc_k1(&self) -> Aes256 {
        Aes256::new_from_slice(&self.key[..32]).expect("k1 boyutu sabit 32 B")
    }
    fn enc_k2(&self) -> Aes256 {
        Aes256::new_from_slice(&self.key[32..]).expect("k2 boyutu sabit 32 B")
    }
}

impl SectorCipher for AesXtsCipher {
    fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(CipherError::InvalidBufferSize);
        }
        let k1 = self.enc_k1();
        let k2 = self.enc_k2();
        raw_xts::xts_encrypt_sector(
            sector,
            sector_index,
            |b| {
                let block = aes::Block::from_mut_slice(b);
                k1.encrypt_block(block);
            },
            |b| {
                let block = aes::Block::from_mut_slice(b);
                k2.encrypt_block(block);
            },
        );
        Ok(())
    }

    fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(CipherError::InvalidBufferSize);
        }
        let k1 = self.enc_k1();
        let k2 = self.enc_k2();
        raw_xts::xts_decrypt_sector(
            sector,
            sector_index,
            |b| {
                let block = aes::Block::from_mut_slice(b);
                k1.decrypt_block(block);
            },
            |b| {
                let block = aes::Block::from_mut_slice(b);
                k2.encrypt_block(block);
            },
        );
        Ok(())
    }
}

impl core::fmt::Debug for AesXtsCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesXtsCipher([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() { *b = i as u8; }
        k
    }

    #[test]
    fn roundtrip_512() {
        let c = AesXtsCipher::new(&key()).unwrap();
        let mut buf = [0x42u8; 512];
        let orig = buf;
        c.encrypt_sector(&mut buf, 0).unwrap();
        assert_ne!(buf, orig);
        c.decrypt_sector(&mut buf, 0).unwrap();
        assert_eq!(buf, orig);
    }

    #[test]
    fn roundtrip_4096() {
        let c = AesXtsCipher::new(&key()).unwrap();
        let mut buf = [0xABu8; 4096];
        let orig = buf;
        c.encrypt_sector(&mut buf, 7).unwrap();
        c.decrypt_sector(&mut buf, 7).unwrap();
        assert_eq!(buf, orig);
    }

    #[test]
    fn sector_index_affects_ciphertext() {
        let c = AesXtsCipher::new(&key()).unwrap();
        let plain = [0x55u8; 512];
        let mut s0 = plain; let mut s1 = plain;
        c.encrypt_sector(&mut s0, 0).unwrap();
        c.encrypt_sector(&mut s1, 1).unwrap();
        assert_ne!(s0, s1);
    }

    #[test]
    fn not_all_zero_ciphertext() {
        let c = AesXtsCipher::new(&[0u8; 64]).unwrap();
        let mut buf = [0u8; 512];
        c.encrypt_sector(&mut buf, 0).unwrap();
        assert_ne!(buf, [0u8; 512]);
    }
}
