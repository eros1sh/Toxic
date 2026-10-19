//! IEEE 1619 XTS — closure tabanlı, trait bağımsız implementasyon.
//!
//! `xts-mode` crate'i kullanılmaz çünkü `Serpent` ve `Twofish` `cipher 0.3.x`
//! trait'lerini implement eder, `xts-mode 0.5.x` ise `cipher 0.4.x` ister.
//! Bu modül cipher sürümünden bağımsız çalışır: şifreleme/çözme işlemleri
//! `FnMut(&mut [u8; 16])` closure olarak geçirilir.
//!
//! # Algoritma (IEEE 1619 §5.2)
//!
//! ```text
//! T_0 = E_K2(sector_index as LE-128)
//! for j in 0..N_blocks:
//!     C_j = E_K1(P_j XOR T_j) XOR T_j
//!     T_{j+1} = T_j * α   (GF(2^128), polinom: x^128 + x^7 + x^2 + x + 1)
//! ```
//!
//! Ciphertext stealing yoktur — sektör boyutu her zaman 16'nın tam katıdır (512/4096 B).

/// Bir alan (sektör) içindeki veriyi XTS ile şifreler.
///
/// # Parametreler
/// - `data`: şifrelenecek tampon (16'nın tam katı uzunluğunda olmalı).
/// - `sector_index`: sektör numarası (tweak).
/// - `enc_k1`: veri şifreleme fonksiyonu — 16 B blok yerinde şifreler.
/// - `enc_k2`: tweak şifreleme fonksiyonu — 16 B blok yerinde şifreler.
pub(crate) fn xts_encrypt_sector<E1, E2>(
    data: &mut [u8],
    sector_index: u64,
    mut enc_k1: E1,
    mut enc_k2: E2,
)
where
    E1: FnMut(&mut [u8; 16]),
    E2: FnMut(&mut [u8; 16]),
{
    debug_assert!(!data.is_empty() && data.len() % 16 == 0);

    let mut tweak = sector_tweak(sector_index, &mut enc_k2);

    for block in data.chunks_exact_mut(16) {
        let blk: &mut [u8; 16] = block.try_into().unwrap();
        // P XOR T
        xor_block(blk, &tweak);
        // E_K1(P XOR T)
        enc_k1(blk);
        // C XOR T
        xor_block(blk, &tweak);
        // T = T * α
        gf_mul_alpha(&mut tweak);
    }
}

/// Bir alan (sektör) içindeki veriyi XTS ile çözer.
///
/// # Parametreler
/// - `data`: çözülecek tampon.
/// - `sector_index`: sektör numarası.
/// - `dec_k1`: veri çözme fonksiyonu — 16 B blok yerinde çözer.
/// - `enc_k2`: tweak şifreleme fonksiyonu (çözmede de şifreleme kullanılır).
pub(crate) fn xts_decrypt_sector<D1, E2>(
    data: &mut [u8],
    sector_index: u64,
    mut dec_k1: D1,
    mut enc_k2: E2,
)
where
    D1: FnMut(&mut [u8; 16]),
    E2: FnMut(&mut [u8; 16]),
{
    debug_assert!(!data.is_empty() && data.len() % 16 == 0);

    let mut tweak = sector_tweak(sector_index, &mut enc_k2);

    for block in data.chunks_exact_mut(16) {
        let blk: &mut [u8; 16] = block.try_into().unwrap();
        // C XOR T
        xor_block(blk, &tweak);
        // D_K1(C XOR T)
        dec_k1(blk);
        // P XOR T
        xor_block(blk, &tweak);
        // T = T * α
        gf_mul_alpha(&mut tweak);
    }
}

// ── Yardımcılar ───────────────────────────────────────────────────────────────

/// Sektör indeksinden başlangıç tweak değerini üretir.
/// Tweak = E_K2(sector_index as LE-128) — IEEE 1619 §5.2.
fn sector_tweak<E2: FnMut(&mut [u8; 16])>(sector_index: u64, enc_k2: &mut E2) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&sector_index.to_le_bytes());
    // t[8..16] sıfır kalır (128-bit LE).
    enc_k2(&mut t);
    t
}

/// İki 16 B tamponu XOR ile karıştırır (yerinde).
#[inline(always)]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// GF(2^128)'de α ile çarpma (T * α = T << 1 mod x^128 + x^7 + x^2 + x + 1).
///
/// Little-endian byte sırası: byte[0] en düşük anlamlı bayt.
#[inline(always)]
fn gf_mul_alpha(t: &mut [u8; 16]) {
    // MSB of last byte (LE: t[15] is most significant byte)
    let carry = (t[15] >> 7) & 1;
    // Left shift entire 128-bit LE value by 1
    for i in (1..16).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
    }
    t[0] <<= 1;
    // Koşullu XOR with 0x87 = x^7 + x^2 + x + 1 (geri besleme polinomu)
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // XOR roundtrip: encrypt(decrypt(x)) = x
    #[test]
    fn xor_roundtrip() {
        let mut a = [0xAAu8; 16];
        let b = [0x55u8; 16];
        xor_block(&mut a, &b);
        xor_block(&mut a, &b);
        assert_eq!(a, [0xAAu8; 16]);
    }

    #[test]
    fn gf_mul_alpha_no_carry() {
        // 0x01 -> 0x02 (sol shift 1 basamak, taşıma yok)
        let mut t = [0u8; 16];
        t[0] = 0x01;
        gf_mul_alpha(&mut t);
        assert_eq!(t[0], 0x02);
        assert_eq!(t[1], 0x00);
    }

    #[test]
    fn gf_mul_alpha_with_carry() {
        // Üst bit dolu: taşıma var, t[0] ^= 0x87
        let mut t = [0u8; 16];
        t[15] = 0x80; // MSB of LE 128-bit = MSB of byte[15]
        gf_mul_alpha(&mut t);
        // Sonuç: 0x87 (polinom geri beslemesi)
        assert_eq!(t[0], 0x87, "GF feedback polinomu hatalı");
        assert_eq!(t[15], 0x00);
    }
}
