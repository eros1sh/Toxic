//! Serpent-256-XTS sektör şifreleme (F-003).
//!
//! Serpent bit-sliced olduğundan sabit zamanlıdır.
//! cipher 0.5.x: Block<Serpent> = Array<u8, U16> (hybrid-array).

use serpent::Serpent;
use serpent::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, Block, KeyInit};
use zeroize::ZeroizeOnDrop;

use crate::{raw_xts, CipherError, SectorCipher, XTS_KEY_SIZE};

/// Serpent-256-XTS şifre cihazı.
#[derive(ZeroizeOnDrop)]
pub struct SerpentXtsCipher {
    key: [u8; XTS_KEY_SIZE],
}

impl SerpentXtsCipher {
    pub fn new(key: &[u8; XTS_KEY_SIZE]) -> Result<Self, CipherError> {
        Ok(SerpentXtsCipher { key: *key })
    }
}

/// `[u8; 16]` → `Block<Serpent>` → şifrele → geri kopyala.
#[inline(always)]
fn enc_block(cipher: &Serpent, b: &mut [u8; 16]) {
    let mut blk = Block::<Serpent>::from(*b);
    cipher.encrypt_block(&mut blk);
    b.copy_from_slice(blk.as_ref());
}

/// `[u8; 16]` → `Block<Serpent>` → çöz → geri kopyala.
#[inline(always)]
fn dec_block(cipher: &Serpent, b: &mut [u8; 16]) {
    let mut blk = Block::<Serpent>::from(*b);
    cipher.decrypt_block(&mut blk);
    b.copy_from_slice(blk.as_ref());
}

impl SectorCipher for SerpentXtsCipher {
    fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(CipherError::InvalidBufferSize);
        }
        let k1 = Serpent::new_from_slice(&self.key[..32]).map_err(|_| CipherError::InvalidKeySize)?;
        let k2 = Serpent::new_from_slice(&self.key[32..]).map_err(|_| CipherError::InvalidKeySize)?;
        raw_xts::xts_encrypt_sector(
            sector,
            sector_index,
            |b| enc_block(&k1, b),
            |b| enc_block(&k2, b),
        );
        Ok(())
    }

    fn decrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(CipherError::InvalidBufferSize);
        }
        let k1 = Serpent::new_from_slice(&self.key[..32]).map_err(|_| CipherError::InvalidKeySize)?;
        let k2 = Serpent::new_from_slice(&self.key[32..]).map_err(|_| CipherError::InvalidKeySize)?;
        raw_xts::xts_decrypt_sector(
            sector,
            sector_index,
            |b| dec_block(&k1, b),
            |b| enc_block(&k2, b),
        );
        Ok(())
    }
}

impl core::fmt::Debug for SerpentXtsCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SerpentXtsCipher([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() { *b = (i * 3) as u8; }
        k
    }

    #[test]
    fn roundtrip() {
        let c = SerpentXtsCipher::new(&key()).unwrap();
        let mut buf = [0x77u8; 512];
        let orig = buf;
        c.encrypt_sector(&mut buf, 5).unwrap();
        assert_ne!(buf, orig);
        c.decrypt_sector(&mut buf, 5).unwrap();
        assert_eq!(buf, orig);
    }

    #[test]
    fn different_from_aes() {
        use crate::AesXtsCipher;
        let k = key();
        let aes = AesXtsCipher::new(&k).unwrap();
        let ser = SerpentXtsCipher::new(&k).unwrap();
        let plain = [0x11u8; 512];
        let mut a = plain;
        let mut s = plain;
        aes.encrypt_sector(&mut a, 0).unwrap();
        ser.encrypt_sector(&mut s, 0).unwrap();
        assert_ne!(a, s);
    }
}
