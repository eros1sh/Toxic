//! Parola işleme: doğrulama, NFC normalleştirmesi ve güvenli temizleme.
//!
//! `Password` türü parola baytlarını tutar ve kapsam dışına çıktığında bellek
//! temizlemesini garantiler (zeroize).

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

/// Maksimum parola uzunluğu (bayt cinsinden, NFC sonrası).
pub const MAX_PASSWORD_BYTES: usize = 256;

/// Sistem volume'ları için izin verilen karakter kümesi (yazdırılabilir ASCII 0x20-0x7E).
const ASCII_PRINTABLE_MIN: u8 = 0x20;
const ASCII_PRINTABLE_MAX: u8 = 0x7E;

/// Doğrulanmış ve normalleştirilmiş parola.
///
/// - Bellekte `zeroize` ile temizlenir (kapsam dışından veya drop'ta).
/// - Normal volume'lar: herhangi bir geçerli UTF-8, NFC normalleştirilmiş, <= 256 bayt.
/// - Sistem volume'ları (`is_system=true`): yalnızca yazdırılabilir ASCII.
#[derive(ZeroizeOnDrop)]
pub struct Password {
    bytes: Zeroizing<alloc::vec::Vec<u8>>,
}

impl Password {
    /// Parola oluşturur ve doğrular.
    ///
    /// # Parametreler
    /// - `raw`: ham parola bytes; tipik olarak kullanıcı girişi veya GUI'den gelen UTF-8
    /// - `is_system`: `true` ise sistem volume'u kısıtları uygulanır (yalnızca ASCII)
    ///
    /// # Hatalar
    /// - `EmptySecret`: boş parola
    /// - `PasswordTooLong`: NFC normalleşme sonrası 256 bayttan uzun
    /// - `PasswordNotAscii`: `is_system=true` ve ASCII olmayan karakter var
    #[cfg(feature = "std")]
    pub fn new(raw: &[u8], is_system: bool) -> Result<Self> {
        if raw.is_empty() {
            return Err(Error::EmptySecret);
        }

        // UTF-8'den str'ye; geçersiz UTF-8 PasswordTooLong olarak ele alınır.
        let raw_str = core::str::from_utf8(raw).map_err(|_| Error::PasswordTooLong)?;

        // NFC normalleştirmesi (Unicode canonical decomposition + canonical composition).
        use unicode_normalization::UnicodeNormalization;
        let normalized: alloc::string::String = raw_str.nfc().collect();
        let norm_bytes = normalized.as_bytes();

        if norm_bytes.len() > MAX_PASSWORD_BYTES {
            return Err(Error::PasswordTooLong);
        }

        if is_system {
            for &b in norm_bytes {
                if b < ASCII_PRINTABLE_MIN || b > ASCII_PRINTABLE_MAX {
                    return Err(Error::PasswordNotAscii);
                }
            }
        }

        let mut v = Zeroizing::new(alloc::vec::Vec::with_capacity(norm_bytes.len()));
        v.extend_from_slice(norm_bytes);
        Ok(Password { bytes: v })
    }

    /// `no_std` ortamları için: NFC normalleştirmesi yapılmaz, ham baytlar doğrudan kullanılır.
    ///
    /// Bootloader ve kernel sürücüsünde `unicode-normalization` mevcut değildir;
    /// UEFI ortamında parola kullanıcıdan ASCII olarak alınır (zorunlu).
    #[cfg(not(feature = "std"))]
    pub fn new(raw: &[u8], is_system: bool) -> Result<Self> {
        if raw.is_empty() {
            return Err(Error::EmptySecret);
        }
        if raw.len() > MAX_PASSWORD_BYTES {
            return Err(Error::PasswordTooLong);
        }
        if is_system {
            for &b in raw {
                if b < ASCII_PRINTABLE_MIN || b > ASCII_PRINTABLE_MAX {
                    return Err(Error::PasswordNotAscii);
                }
            }
        }

        let mut v = Zeroizing::new(alloc::vec::Vec::with_capacity(raw.len()));
        v.extend_from_slice(raw);
        Ok(Password { bytes: v })
    }

    /// Normalleştirilmiş parola baytlarını döner.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Uzunluğu bayt cinsinden döner (NFC normalleşme sonrası).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Parola boş mu? (`EmptySecret` hatası zaten engeller; bu yalnızca debug için).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl core::fmt::Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Password([redacted])")
    }
}

// alloc import (no_std uyumu)
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_rejected() {
        assert_eq!(Password::new(b"", false).unwrap_err(), Error::EmptySecret);
    }

    #[test]
    fn too_long_password_rejected() {
        let long = alloc::vec![b'a'; MAX_PASSWORD_BYTES + 1];
        assert_eq!(Password::new(&long, false).unwrap_err(), Error::PasswordTooLong);
    }

    #[test]
    fn exact_max_length_accepted() {
        let exact = alloc::vec![b'a'; MAX_PASSWORD_BYTES];
        assert!(Password::new(&exact, false).is_ok());
    }

    #[test]
    fn system_volume_ascii_ok() {
        assert!(Password::new(b"hunter2!", true).is_ok());
    }

    #[test]
    fn system_volume_non_ascii_rejected() {
        // UTF-8 ile kodlanmış Türkçe 'ü' karakteri (2 bayt: 0xC3 0xBC).
        let with_umlaut = "Sifre_\u{00FC}".as_bytes();
        assert_eq!(
            Password::new(with_umlaut, true).unwrap_err(),
            Error::PasswordNotAscii
        );
    }

    #[test]
    fn normal_volume_non_ascii_ok() {
        let with_umlaut = "Sifre_\u{00FC}".as_bytes();
        assert!(Password::new(with_umlaut, false).is_ok());
    }

    #[test]
    fn password_bytes_roundtrip() {
        let pw = Password::new(b"test123", false).unwrap();
        assert_eq!(pw.as_bytes(), b"test123");
        assert_eq!(pw.len(), 7);
    }

    // NFC normalleştirme testi; yalnızca std özelliğinde çalışır.
    #[cfg(feature = "std")]
    #[test]
    fn nfc_normalization() {
        // "u" + combining umlaut (NFD) == "u-umlaut" (NFC).
        // Her ikisi de aynı NFC normalleştirmesine dönüşmeli.
        let nfd = "u\u{0308}"; // u + combining diaeresis
        let nfc = "\u{00FC}";  // u with diaeresis

        let pw_nfd = Password::new(nfd.as_bytes(), false).unwrap();
        let pw_nfc = Password::new(nfc.as_bytes(), false).unwrap();

        // Her ikisi NFC'ye normalleştirilmiş olmalı.
        assert_eq!(pw_nfd.as_bytes(), pw_nfc.as_bytes());
    }
}
