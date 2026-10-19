//! ADR-003 §3 — Slot seal/open (XChaCha20-Poly1305).
//!
//! Her slot 4 KiB'dir ve şu yapıdadır:
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │  nonce        24 B  (rastgele, XChaCha20)    │
//! │  ciphertext  128 B  (aşağıya bakın)          │
//! │  tag          16 B  (Poly1305)               │
//! │  padding    3928 B  (sıfır, AEAD dışı)       │
//! └──────────────────────────────────────────────┘
//!
//! Ciphertext içeriği (plaintext 128 B):
//!   master_key_enc  32 B  (XTS şifreleme alt-anahtarı)
//!   master_key_twk  32 B  (XTS tweak alt-anahtarı)
//!   meta_key        32 B  (metadata bloğu AEAD anahtarı)
//!   reserved        32 B  (sıfır; gelecek kullanım)
//! Toplam: 128 B  →  ciphertext: 128 B + tag: 16 B = 144 B
//! ```
//!
//! AAD = `b"toxic-header-v1"` (ADR-003 §3).
//! Nonce 24 B → XChaCha20 (uzun nonce, tekrarlama riski ihmal edilebilir seviyede).

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error, Result, HEADER_AAD, NONCE_LEN, SLOT_COUNT, SLOT_SIZE,
    SALT_LEN,
};

// ── Slot plaintext layout ──────────────────────────────────────────────────────

/// Slot içindeki plaintext uzunluğu (128 B).
pub const SLOT_PLAINTEXT_LEN: usize = 128;
/// Şifrelenmiş veri + tag (144 B).
pub const SLOT_CIPHERTEXT_AND_TAG_LEN: usize = SLOT_PLAINTEXT_LEN + 16;
/// Slot içindeki pad alanı (3928 B).
pub const SLOT_PADDING_LEN: usize = SLOT_SIZE - NONCE_LEN - SLOT_CIPHERTEXT_AND_TAG_LEN;

const _: () = assert!(
    NONCE_LEN + SLOT_CIPHERTEXT_AND_TAG_LEN + SLOT_PADDING_LEN == SLOT_SIZE,
    "slot boyutu uyumsuz"
);

// ── Slot payload ──────────────────────────────────────────────────────────────

/// Bir slottan çözülen master key materyali.
#[derive(ZeroizeOnDrop)]
pub struct SlotPayload {
    /// XTS şifreleme alt-anahtarı (32 B).
    pub master_key_enc: [u8; 32],
    /// XTS tweak alt-anahtarı (32 B).
    pub master_key_twk: [u8; 32],
    /// Metadata bloğu AEAD anahtarı (32 B).
    pub meta_key: [u8; 32],
    // reserved 32 B alanı saklanmaz.
}

impl core::fmt::Debug for SlotPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SlotPayload([redacted])")
    }
}

impl SlotPayload {
    /// 128 B plaintext tamponundan parse eder.
    fn from_bytes(buf: &[u8; SLOT_PLAINTEXT_LEN]) -> Self {
        let mut enc = [0u8; 32];
        let mut twk = [0u8; 32];
        let mut meta = [0u8; 32];
        enc.copy_from_slice(&buf[0..32]);
        twk.copy_from_slice(&buf[32..64]);
        meta.copy_from_slice(&buf[64..96]);
        SlotPayload { master_key_enc: enc, master_key_twk: twk, meta_key: meta }
    }

    /// 128 B plaintext tamponuna yazar. Çağrı sonrası tampon sıfırlanmalıdır.
    fn to_bytes(&self) -> Zeroizing<[u8; SLOT_PLAINTEXT_LEN]> {
        let mut buf = Zeroizing::new([0u8; SLOT_PLAINTEXT_LEN]);
        buf[0..32].copy_from_slice(&self.master_key_enc);
        buf[32..64].copy_from_slice(&self.master_key_twk);
        buf[64..96].copy_from_slice(&self.meta_key);
        // buf[96..128] = 0 (reserved)
        buf
    }
}

// ── AEAD anahtar türetme ───────────────────────────────────────────────────────

/// Slot AEAD anahtarı için gerekli materyal.
///
/// Slot anahtarı doğrudan `derive_header_key` çıktısından gelir (32 B).
/// Bu struct, güvenli iletim amacıyla ZeroizeOnDrop implementasyonu taşır.
#[derive(ZeroizeOnDrop)]
pub struct SlotKey {
    inner: [u8; 32],
}

impl core::fmt::Debug for SlotKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SlotKey([redacted])")
    }
}

impl SlotKey {
    /// Türetilmiş 32 B anahtardan oluşturur.
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        SlotKey { inner: *key_bytes }
    }
}

// ── Seal ──────────────────────────────────────────────────────────────────────

/// Bir slot gövdesini (4 KiB tampon) `payload` ile mühürler.
///
/// `nonce_bytes` 24 B rastgele değer olmalıdır — çağrı CSPRNG kullanımından sorumludur.
/// `out_slot` tam 4 KiB tampon olmalıdır.
///
/// `encrypt_in_place_detached` yerinde çalışır ve tag döner; plaintext önce kopyalanır.
pub fn seal_slot(
    out_slot: &mut [u8; SLOT_SIZE],
    payload: &SlotPayload,
    key: &SlotKey,
    nonce_bytes: &[u8; NONCE_LEN],
) -> Result<()> {
    out_slot.zeroize();
    out_slot[..NONCE_LEN].copy_from_slice(nonce_bytes);

    let ct_start = NONCE_LEN;
    let ct_end   = NONCE_LEN + SLOT_PLAINTEXT_LEN;
    let tag_end  = ct_end + 16;

    // Plaintext'i slot tamponuna kopyala; plaintext şifreli metne dönüştürülecek.
    let pt = payload.to_bytes();
    out_slot[ct_start..ct_end].copy_from_slice(pt.as_ref());
    // pt burada drop olur ve ZeroizeOnDrop tetiklenir.
    drop(pt);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.inner));
    let nonce  = XNonce::from_slice(nonce_bytes);

    let tag = cipher
        .encrypt_in_place_detached(nonce, HEADER_AAD, &mut out_slot[ct_start..ct_end])
        .map_err(|_| Error::SlotSeal)?;

    out_slot[ct_end..tag_end].copy_from_slice(&tag);
    Ok(())
}

// ── Open ──────────────────────────────────────────────────────────────────────

/// Bir slot gövdesini (4 KiB) açar; başarıyla çözülürse `SlotPayload` döner.
///
/// Hatalı anahtar → `Err(Error::SlotOpen)`.
pub fn open_slot(slot: &[u8; SLOT_SIZE], key: &SlotKey) -> Result<SlotPayload> {
    let nonce_bytes = &slot[..NONCE_LEN];
    let ct_start    = NONCE_LEN;
    let ct_end      = NONCE_LEN + SLOT_PLAINTEXT_LEN;
    let tag_end     = ct_end + 16;

    // Çözme için ciphertext + tag kopyası.
    let mut ct_buf = Zeroizing::new([0u8; SLOT_PLAINTEXT_LEN]);
    ct_buf.copy_from_slice(&slot[ct_start..ct_end]);

    let tag_bytes = chacha20poly1305::Tag::clone_from_slice(&slot[ct_end..tag_end]);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.inner));
    let nonce  = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt_in_place_detached(nonce, HEADER_AAD, &mut *ct_buf, &tag_bytes)
        .map_err(|_| Error::SlotOpen)?;

    // Güvenli karşılaştırma: reserved 32 B sıfır olmalı (F-059 §integrity).
    use subtle::ConstantTimeEq;
    let reserved_ok: bool = ct_buf[96..128].ct_eq(&[0u8; 32]).into();
    if !reserved_ok {
        ct_buf.zeroize();
        return Err(Error::SlotOpen);
    }

    let pt_arr: [u8; SLOT_PLAINTEXT_LEN] = *ct_buf;
    Ok(SlotPayload::from_bytes(&pt_arr))
}

// ── Yardımcı: header region ───────────────────────────────────────────────────

/// Header region boyutu: bölge tuzu + 8 slot = 32 + 8×4096 = 32800 B.
/// ADR-003 §2: tüm region 65536 B olarak yuvarlak hizalanır (kalan = rastgele dolgu).
pub const HEADER_REGION_SIZE: usize = SALT_LEN + SLOT_COUNT * SLOT_SIZE;

/// Bir header region tamponundan `slot_index` numaralı slotu döner.
pub fn get_slot(region: &[u8], slot_index: usize) -> Result<&[u8; SLOT_SIZE]> {
    if slot_index >= SLOT_COUNT {
        return Err(Error::InvalidSlotIndex);
    }
    let offset = SALT_LEN + slot_index * SLOT_SIZE;
    let arr: &[u8; SLOT_SIZE] = region[offset..offset + SLOT_SIZE]
        .try_into()
        .map_err(|_| Error::InvalidSlotIndex)?;
    Ok(arr)
}

/// Bir header region tamponundaki `slot_index` numaralı slota yazar (mutable).
pub fn get_slot_mut(region: &mut [u8], slot_index: usize) -> Result<&mut [u8; SLOT_SIZE]> {
    if slot_index >= SLOT_COUNT {
        return Err(Error::InvalidSlotIndex);
    }
    let offset = SALT_LEN + slot_index * SLOT_SIZE;
    let arr: &mut [u8; SLOT_SIZE] = (&mut region[offset..offset + SLOT_SIZE])
        .try_into()
        .map_err(|_| Error::InvalidSlotIndex)?;
    Ok(arr)
}

// ── Testler ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_payload() -> SlotPayload {
        SlotPayload {
            master_key_enc: [0xAAu8; 32],
            master_key_twk: [0xBBu8; 32],
            meta_key:       [0xCCu8; 32],
        }
    }

    fn dummy_key() -> SlotKey {
        SlotKey::new(&[0x42u8; 32])
    }

    fn dummy_nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() { *b = i as u8; }
        n
    }

    #[test]
    fn seal_open_roundtrip() {
        let payload = dummy_payload();
        let key     = dummy_key();
        let nonce   = dummy_nonce();
        let mut slot = [0u8; SLOT_SIZE];

        seal_slot(&mut slot, &payload, &key, &nonce).expect("seal başarısız");

        let recovered = open_slot(&slot, &key).expect("open başarısız");

        assert_eq!(recovered.master_key_enc, payload.master_key_enc);
        assert_eq!(recovered.master_key_twk, payload.master_key_twk);
        assert_eq!(recovered.meta_key,       payload.meta_key);
    }

    #[test]
    fn wrong_key_fails() {
        let payload = dummy_payload();
        let key     = dummy_key();
        let nonce   = dummy_nonce();
        let mut slot = [0u8; SLOT_SIZE];

        seal_slot(&mut slot, &payload, &key, &nonce).unwrap();

        let bad_key = SlotKey::new(&[0xFFu8; 32]);
        assert!(open_slot(&slot, &bad_key).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let payload = dummy_payload();
        let key     = dummy_key();
        let nonce   = dummy_nonce();
        let mut slot = [0u8; SLOT_SIZE];

        seal_slot(&mut slot, &payload, &key, &nonce).unwrap();
        // Ciphertext'in ortasını değiştir.
        slot[NONCE_LEN + 64] ^= 0xFF;
        assert!(open_slot(&slot, &key).is_err());
    }

    #[test]
    fn nonce_is_stored() {
        let payload = dummy_payload();
        let key     = dummy_key();
        let nonce   = dummy_nonce();
        let mut slot = [0u8; SLOT_SIZE];

        seal_slot(&mut slot, &payload, &key, &nonce).unwrap();
        assert_eq!(&slot[..NONCE_LEN], &nonce);
    }

    #[test]
    fn get_slot_index_bounds() {
        let region = vec![0u8; SALT_LEN + SLOT_COUNT * SLOT_SIZE];
        assert!(get_slot(&region, 0).is_ok());
        assert!(get_slot(&region, 7).is_ok());
        assert!(get_slot(&region, 8).is_err());
    }
}
