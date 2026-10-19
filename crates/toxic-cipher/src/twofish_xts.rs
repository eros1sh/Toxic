//! Twofish-256-XTS sektör şifreleme (F-004).
//!
//! Uyarı: Twofish tablo tabanlıdır; önbellek zamanlama yan kanalı teorik olarak
//! mümkündür. Düşük tehdit seviyesinde belgelenmiş kabul edilmiş risktir.
//! cipher 0.5.x: Block<Twofish> = Array<u8, U16> (hybrid-array).

use twofish::Twofish;
use twofish::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, Block, KeyInit};
use zeroize::ZeroizeOnDrop;

use crate::{raw_xts, CipherError, SectorCipher, XTS_KEY_SIZE};

/// Twofish-256-XTS şifre cihazı.
#[derive(ZeroizeOnDrop)]
pub struct TwofishXtsCipher {
    key: [u8; XTS_KEY_SIZE],
}

impl TwofishXtsCipher {
    pub fn new(key: &[u8; XTS_KEY_SIZE]) -> Result<Self, CipherError> {
        Ok(TwofishXtsCipher { key: *key })
    }
}

/// `[u8; 16]` → `Block<Twofish>` → şifrele → geri kopyala.
#[inline(always)]
fn enc_block(cipher: &Twofish, b: &mut [u8; 16]) {
    let mut blk = Block::<Twofish>::from(*b);
    cipher.encrypt_block(&mut blk);
    b.copy_from_slice(blk.as_ref());
}

/// `[u8; 16]` → `Block<Twofish>` → çöz → geri kopyala.
#[inline(always)]
fn dec_block(cipher: &Twofish, b: &mut [u8; 16]) {
    let mut blk = Block::<Twofish>::from(*b);
    cipher.decrypt_block(&mut blk);
    b.copy_from_slice(blk.as_ref());
}

impl SectorCipher for TwofishXtsCipher {
    fn encrypt_sector(&self, sector: &mut [u8], sector_index: u64) -> Result<(), CipherError> {
        if sector.is_empty() || sector.len() % 16 != 0 {
            return Err(CipherError::InvalidBufferSize);
        }
        let k1 = Twofish::new_from_slice(&self.key[..32]).map_err(|_| CipherError::InvalidKeySize)?;
        let k2 = Twofish::new_from_slice(&self.key[32..]).map_err(|_| CipherError::InvalidKeySize)?;
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
        let k1 = Twofish::new_from_slice(&self.key[..32]).map_err(|_| CipherError::InvalidKeySize)?;
        let k2 = Twofish::new_from_slice(&self.key[32..]).map_err(|_| CipherError::InvalidKeySize)?;
        raw_xts::xts_decrypt_sector(
            sector,
            sector_index,
            |b| dec_block(&k1, b),
            |b| enc_block(&k2, b),
        );
        Ok(())
    }
}

impl core::fmt::Debug for TwofishXtsCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TwofishXtsCipher([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 64] {
        let mut k = [0xFFu8; 64];
        for (i, b) in k.iter_mut().enumerate() { *b = (0xFF - i) as u8; }
        k
    }

    #[test]
    fn roundtrip() {
        let c = TwofishXtsCipher::new(&key()).unwrap();
        let mut buf = [0xCCu8; 512];
        let orig = buf;
        c.encrypt_sector(&mut buf, 3).unwrap();
        assert_ne!(buf, orig);
        c.decrypt_sector(&mut buf, 3).unwrap();
        assert_eq!(buf, orig);
    }
}
