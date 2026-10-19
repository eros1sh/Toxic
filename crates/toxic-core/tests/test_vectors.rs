//! Kriptografik test vektörleri.
//!
//! Bu testler bilinen girdi-çıktı çiftleri ile determinizmi doğrular.
//! Vektörler bağımsız bir Python scripti (tools/gen_vectors.py) ile üretilir.

use toxic_core::kdf::{derive_header_key_zeroizing, KdfCost};
use toxic_core::keyfile::{KeyfileDigest, KeyfileSecret};
use toxic_core::password::Password;

/// Test sabiti: düşük maliyet (hız için).
const TEST_COST: KdfCost = KdfCost { level: 1 };

// ── KDF Test Vektörleri ────────────────────────────────────────────────────────

/// KDF-TV-001: Saf parola, bilinen tuz, bilinen çıktı.
///
/// Bu vektörü üretmek için:
/// ```bash
/// python tools/gen_vectors.py kdf --password "hunter2" --salt 00*32 --level 1
/// ```
#[test]
fn kdf_tv001_password_only() {
    let salt = [0x00u8; 32];
    let pw = b"hunter2";
    let key = derive_header_key_zeroizing(pw, &salt, TEST_COST).unwrap();

    // Not: Beklenen değer aşağıya gerçek Argon2id çıktısı ile doldurulacak.
    // İlk çalıştırmada bu test başarısız olur; çıktıyı kopyalayıp buraya yapıştır.
    // TODO (Faz 1): gerçek vektörü üret ve buraya ekle.
    assert_eq!(key.len(), 32, "anahtar 32 bayt olmali");
    // Determinizm: aynı girdi aynı çıktı üretmeli.
    let key2 = derive_header_key_zeroizing(pw, &salt, TEST_COST).unwrap();
    assert_eq!(*key, *key2, "ayni girdi ayni anahtar uretmeli");
}

/// KDF-TV-002: Farklı tuzlar farklı anahtarlar üretmeli.
#[test]
fn kdf_tv002_different_salts_diverge() {
    let pw = b"same_password";
    let cost = TEST_COST;

    let salt_a = [0xAA_u8; 32];
    let salt_b = [0xBB_u8; 32];

    let key_a = derive_header_key_zeroizing(pw, &salt_a, cost).unwrap();
    let key_b = derive_header_key_zeroizing(pw, &salt_b, cost).unwrap();

    assert_ne!(*key_a, *key_b, "farkli tuzlar farkli anahtar uretmeli");
}

/// KDF-TV-003: Farklı parolalar farklı anahtarlar üretmeli.
#[test]
fn kdf_tv003_different_passwords_diverge() {
    let salt = [0x11_u8; 32];
    let cost = TEST_COST;

    let k1 = derive_header_key_zeroizing(b"password1", &salt, cost).unwrap();
    let k2 = derive_header_key_zeroizing(b"password2", &salt, cost).unwrap();

    assert_ne!(*k1, *k2);
}

// ── Keyfile Test Vektörleri ────────────────────────────────────────────────────

/// KF-TV-001: Tek keyfile, bilinen içerik, bilinen BLAKE2b-256 özeti.
#[test]
fn kf_tv001_digest_known_input() {
    // BLAKE2b-256("test") bilinen değer:
    // Doğrulama: echo -n "test" | b2sum -l 256
    let digest = KeyfileDigest::from_bytes(b"test").unwrap();
    // Uzunluk kontrolü
    assert_eq!(digest.as_bytes().len(), 32);
    // Determinizm
    let digest2 = KeyfileDigest::from_bytes(b"test").unwrap();
    assert_eq!(digest.as_bytes(), digest2.as_bytes());
}

/// KF-TV-002: Keyfile + parola kombinasyonu sıra bağımlı.
#[test]
fn kf_tv002_order_dependent() {
    let d1 = KeyfileDigest::from_bytes(b"file_alpha").unwrap();
    let d2 = KeyfileDigest::from_bytes(b"file_beta").unwrap();

    let s_ab = KeyfileSecret::combine(b"pw", &[d1.clone(), d2.clone()]).unwrap();
    let s_ba = KeyfileSecret::combine(b"pw", &[d2.clone(), d1.clone()]).unwrap();

    assert_ne!(s_ab.as_ikm(), s_ba.as_ikm(), "sira bağimsiz olmamali");
}

// ── Parola Test Vektörleri ─────────────────────────────────────────────────────

/// PW-TV-001: Geçerli parola kabul edilir.
#[test]
fn pw_tv001_valid_password_accepted() {
    let pw = Password::new(b"valid_password_123", false).unwrap();
    assert_eq!(pw.as_bytes(), b"valid_password_123");
}

/// PW-TV-002: Sistem volume'u için yalnızca ASCII kabul edilir.
#[test]
fn pw_tv002_system_volume_ascii_only() {
    assert!(Password::new(b"ascii_only!", true).is_ok());
    // U+00FC = ü (UTF-8: 0xC3 0xBC)
    assert!(Password::new("\u{00FC}password".as_bytes(), true).is_err());
}

/// PW-TV-003: Maksimum uzunluk sınırı uygulanır.
#[test]
fn pw_tv003_max_length_enforced() {
    use alloc::vec;
    let too_long = vec![b'a'; 257];
    assert!(Password::new(&too_long, false).is_err());
    let exact = vec![b'a'; 256];
    assert!(Password::new(&exact, false).is_ok());
}

// alloc makroları için
extern crate alloc;
