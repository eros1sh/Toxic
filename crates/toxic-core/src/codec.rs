//! ADR-003 §2 — 64 KiB header bölgesi encode/decode.
//!
//! Header bölgesi yapısı:
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │  region_salt    32 B   (Argon2id salt, rastgele)         │
//! │  slot[0]      4096 B   (ADR-003 §3)                      │
//! │  slot[1]      4096 B                                     │
//! │  …                                                       │
//! │  slot[7]      4096 B                                     │
//! │  meta_block   4096 B   (XChaCha20-Poly1305, ADR-003 §5) │
//! │  padding     29664 B   (rastgele veya sıfır)             │
//! └──────────────────────────────────────────────────────────┘
//! Toplam: 65536 B = 64 KiB
//! ```
//!
//! `Codec` operasyonları:
//! - `build_region`: boş 64 KiB tampon oluşturur, salt + slot'ları yerleştirir.
//! - `read_region_salt`: tampondan region salt'ı okur.
//! - `try_open_any_slot`: sırayla her slot'u dener, ilk başarılı slot payloadu döner.
//! - `write_slot`: belirli bir slot'a mühürlü veri yazar.
//! - `META_BLOCK_OFFSET` / `META_BLOCK_SIZE`: meta blok konumu.

use zeroize::Zeroize;

use crate::{
    layout::RegionSalt,
    slot::{open_slot, seal_slot, SlotKey, SlotPayload},
    Error, Result, NONCE_LEN, SALT_LEN, SLOT_COUNT, SLOT_SIZE,
};

// ── Sabitler ─────────────────────────────────────────────────────────────────

/// Header bölgesinin toplam boyutu: 64 KiB.
pub const REGION_SIZE: usize = 65_536;

/// Meta bloğunun header bölgesindeki başlangıç offseti.
pub const META_BLOCK_OFFSET: usize = SALT_LEN + SLOT_COUNT * SLOT_SIZE;
/// Meta bloğunun boyutu: 4096 B (şifrelenmiş metadata + tag + padding).
pub const META_BLOCK_SIZE: usize = 4_096;

const _: () = assert!(
    SALT_LEN + SLOT_COUNT * SLOT_SIZE + META_BLOCK_SIZE <= REGION_SIZE,
    "meta blok region'a sığmıyor"
);

// ── Yardımcı tipler ───────────────────────────────────────────────────────────

/// Header bölgesi kodlama sonucu.
pub struct RegionView<'a> {
    /// Ham 64 KiB tampon (sadece okunabilir).
    pub raw: &'a [u8; REGION_SIZE],
}

impl core::fmt::Debug for RegionView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RegionView([65536 bytes])")
    }
}

// ── Oluşturma ─────────────────────────────────────────────────────────────────

/// Boş bir 64 KiB header bölgesi tampon döner; salt yerleştirilir.
///
/// Sıfır bant genişliği için `out_region` dışarıdan verilir (heap/stack kararı çağrıya bırakılır).
/// `out_region` çağrı öncesi herhangi bir içerikle dolu olabilir; fonksiyon tamamını sıfırlar.
pub fn build_empty_region(out_region: &mut [u8; REGION_SIZE], salt: &RegionSalt) {
    out_region.zeroize();
    out_region[..SALT_LEN].copy_from_slice(salt.as_ref());
}

/// Header bölgesinin salt alanını okur.
pub fn read_region_salt(region: &[u8; REGION_SIZE]) -> RegionSalt {
    let mut s = [0u8; SALT_LEN];
    s.copy_from_slice(&region[..SALT_LEN]);
    RegionSalt::from(s)
}

// ── Slot yazma / okuma ────────────────────────────────────────────────────────

/// Belirli bir slot'a mühürlü veri yazar.
///
/// `slot_index` 0–7 aralığında olmalıdır.
pub fn write_slot(
    region: &mut [u8; REGION_SIZE],
    slot_index: usize,
    payload: &SlotPayload,
    key: &SlotKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<()> {
    if slot_index >= SLOT_COUNT {
        return Err(Error::InvalidSlotIndex);
    }
    let offset = SALT_LEN + slot_index * SLOT_SIZE;
    let slot_buf: &mut [u8; SLOT_SIZE] = (&mut region[offset..offset + SLOT_SIZE])
        .try_into()
        .map_err(|_| Error::Codec)?;
    seal_slot(slot_buf, payload, key, nonce)
}

/// Tüm slot'ları sırayla deneyerek ilk başarılıyı açar.
///
/// Döner: `Ok((slot_index, SlotPayload))` veya hiç açılamazsa `Err(InvalidCredentials)`.
pub fn try_open_any_slot(
    region: &[u8; REGION_SIZE],
    key: &SlotKey,
) -> Result<(usize, SlotPayload)> {
    for i in 0..SLOT_COUNT {
        let offset = SALT_LEN + i * SLOT_SIZE;
        let slot_buf: &[u8; SLOT_SIZE] = region[offset..offset + SLOT_SIZE]
            .try_into()
            .map_err(|_| Error::Codec)?;

        if let Ok(payload) = open_slot(slot_buf, key) {
            return Ok((i, payload));
        }
    }
    Err(Error::InvalidCredentials)
}

/// Belirli bir slot'u açmayı dener.
pub fn try_open_slot(
    region: &[u8; REGION_SIZE],
    slot_index: usize,
    key: &SlotKey,
) -> Result<SlotPayload> {
    if slot_index >= SLOT_COUNT {
        return Err(Error::InvalidSlotIndex);
    }
    let offset = SALT_LEN + slot_index * SLOT_SIZE;
    let slot_buf: &[u8; SLOT_SIZE] = region[offset..offset + SLOT_SIZE]
        .try_into()
        .map_err(|_| Error::Codec)?;
    open_slot(slot_buf, key)
}

// ── Meta blok ─────────────────────────────────────────────────────────────────

/// Meta blok tamponunu döner (değiştirilemez).
pub fn meta_block(region: &[u8; REGION_SIZE]) -> &[u8; META_BLOCK_SIZE] {
    region[META_BLOCK_OFFSET..META_BLOCK_OFFSET + META_BLOCK_SIZE]
        .try_into()
        .expect("meta blok boyutu sabit")
}

/// Meta blok tamponunu döner (değiştirilebilir).
pub fn meta_block_mut(region: &mut [u8; REGION_SIZE]) -> &mut [u8; META_BLOCK_SIZE] {
    (&mut region[META_BLOCK_OFFSET..META_BLOCK_OFFSET + META_BLOCK_SIZE])
        .try_into()
        .expect("meta blok boyutu sabit")
}

// ── Testler ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{layout::RegionSalt, slot::{SlotKey, SlotPayload}};

    fn make_region() -> Box<[u8; REGION_SIZE]> {
        // Box kullan — 64 KiB stack frame'i patlatmasın.
        Box::new([0u8; REGION_SIZE])
    }

    fn dummy_payload() -> SlotPayload {
        SlotPayload {
            master_key_enc: [0xA1u8; 32],
            master_key_twk: [0xB2u8; 32],
            meta_key:       [0xC3u8; 32],
        }
    }

    fn dummy_key() -> SlotKey {
        SlotKey::new(&[0x55u8; 32])
    }

    fn dummy_nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() { *b = (i + 10) as u8; }
        n
    }

    #[test]
    fn build_and_read_salt() {
        let mut region = make_region();
        let salt_bytes = [0x42u8; SALT_LEN];
        let salt = RegionSalt::from(salt_bytes);
        build_empty_region(&mut region, &salt);

        let recovered = read_region_salt(&region);
        assert_eq!(recovered.as_ref(), &salt_bytes);
    }

    #[test]
    fn write_and_open_slot_0() {
        let mut region = make_region();
        let salt = RegionSalt::from([0xFEu8; SALT_LEN]);
        build_empty_region(&mut region, &salt);

        let key     = dummy_key();
        let payload = dummy_payload();
        let nonce   = dummy_nonce();

        write_slot(&mut region, 0, &payload, &key, &nonce).unwrap();

        let (idx, recovered) = try_open_any_slot(&region, &key).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(recovered.master_key_enc, payload.master_key_enc);
        assert_eq!(recovered.meta_key,       payload.meta_key);
    }

    #[test]
    fn write_slot_7_and_open() {
        let mut region = make_region();
        let salt = RegionSalt::from([0x11u8; SALT_LEN]);
        build_empty_region(&mut region, &salt);

        let key     = dummy_key();
        let payload = dummy_payload();
        let nonce   = dummy_nonce();

        write_slot(&mut region, 7, &payload, &key, &nonce).unwrap();

        let result = try_open_slot(&region, 7, &key).unwrap();
        assert_eq!(result.master_key_twk, payload.master_key_twk);
    }

    #[test]
    fn invalid_slot_index() {
        let mut region = make_region();
        let salt = RegionSalt::from([0u8; SALT_LEN]);
        build_empty_region(&mut region, &salt);
        let key  = dummy_key();
        let nonce = dummy_nonce();
        let payload = dummy_payload();

        assert!(write_slot(&mut region, 8, &payload, &key, &nonce).is_err());
        assert!(try_open_slot(&region, 8, &key).is_err());
    }

    #[test]
    fn wrong_key_returns_invalid_credentials() {
        let mut region = make_region();
        let salt = RegionSalt::from([0x22u8; SALT_LEN]);
        build_empty_region(&mut region, &salt);

        let good_key = dummy_key();
        let bad_key  = SlotKey::new(&[0xAAu8; 32]);
        let payload  = dummy_payload();
        let nonce    = dummy_nonce();

        write_slot(&mut region, 3, &payload, &good_key, &nonce).unwrap();

        assert_eq!(
            try_open_any_slot(&region, &bad_key).unwrap_err(),
            Error::InvalidCredentials,
        );
    }

    #[test]
    fn meta_block_offset_correct() {
        let region = make_region();
        let _mb = meta_block(&region); // panicsiz erişilmeli
        assert_eq!(META_BLOCK_OFFSET, SALT_LEN + SLOT_COUNT * SLOT_SIZE);
    }
}
