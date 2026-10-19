use core::fmt;

/// `toxic-core` işlemlerinin sonuç tipi.
pub type Result<T> = core::result::Result<T, Error>;

/// Çekirdek hata tipi.
///
/// `InvalidCredentials` yanlış parola, yanlış keyfile, yanlış maliyet seviyesi, bozuk ve değiştirilmiş
/// header durumlarının hepsini kapsar; spesifikasyon gereği bu durumlar birbirinden ayrılmaz (§1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Header açılamadı (parola, keyfile veya maliyet seviyesi yanlış ya da header bozuk).
    InvalidCredentials,
    /// AEAD doğrulamasını geçti ama içerik spesifikasyona uymuyor (yazıcı hatası).
    CorruptHeader,
    /// Header bu sürümün desteklemediği bir özellik veya sürüm içeriyor.
    UnsupportedHeader,
    /// Maliyet seviyesi geçerli aralığın dışında.
    InvalidCost,
    /// Parola 256 bayttan uzun.
    PasswordTooLong,
    /// Sistem volume'u parolası yazdırılabilir ASCII dışında karakter içeriyor.
    PasswordNotAscii,
    /// Parola boş ve keyfile verilmemiş.
    EmptySecret,
    /// Boş (0 bayt) keyfile.
    EmptyKeyfile,
    /// 64'ten fazla keyfile.
    TooManyKeyfiles,
    /// Desteklenmeyen sektör boyutu.
    InvalidSectorSize,
    /// Volume boyutu veya veri alanı düzene uymuyor.
    InvalidLayout,
    /// Verilen tamponun boyutu beklenenle uyuşmuyor ya da hizalı değil.
    BufferSize,
    /// Rastgele sayı üreteci başarısız oldu.
    Rng,
    /// Argon2id hesaplaması başarısız oldu.
    Kdf,
    /// AEAD şifreleme başarısız oldu.
    Aead,
    /// Slot mühürleme (seal) işlemi başarısız oldu.
    SlotSeal,
    /// Slot açma (open) işlemi başarısız oldu; anahtar hatalı veya veri bozuk.
    SlotOpen,
    /// Slot indeksi geçersiz (0–7 dışında).
    InvalidSlotIndex,
    /// Header codec çözme/oluşturma hatası.
    Codec,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidCredentials => "parola, keyfile veya maliyet seviyesi hatalı ya da header bozuk",
            Self::CorruptHeader => "header içeriği spesifikasyona uymuyor",
            Self::UnsupportedHeader => "header bu sürümün desteklemediği bir format kullanıyor",
            Self::InvalidCost => "maliyet seviyesi 1 ile 64 arasında olmalı (sistem volume'larında en fazla 16)",
            Self::PasswordTooLong => "parola en fazla 256 bayt olabilir",
            Self::PasswordNotAscii => "sistem şifrelemesi parolası yalnızca İngilizce klavye karakterleri içerebilir",
            Self::EmptySecret => "parola boş olamaz (keyfile kullanılmıyorsa)",
            Self::EmptyKeyfile => "keyfile boş olamaz",
            Self::TooManyKeyfiles => "en fazla 64 keyfile kullanılabilir",
            Self::InvalidSectorSize => "sektör boyutu 512 veya 4096 olmalı",
            Self::InvalidLayout => "volume boyutu veya veri alanı geçersiz",
            Self::BufferSize => "tampon boyutu geçersiz ya da hizalı değil",
            Self::Rng => "rastgele sayı üreteci başarısız oldu",
            Self::Kdf => "anahtar türetme başarısız oldu",
            Self::Aead              => "header şifreleme başarısız oldu",
            Self::SlotSeal          => "slot mühürleme başarısız oldu",
            Self::SlotOpen          => "slot açma başarısız oldu; anahtar hatalı veya veri bozuk",
            Self::InvalidSlotIndex  => "slot indeksi 0–7 arasında olmalı",
            Self::Codec             => "header codec hatası",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
