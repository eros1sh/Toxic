//! Volume header tipleri: `VolumeHeader`, `MasterKey`, `Flags`, `SectorSize`.
//!
//! Bu modul ADR-003 cok-slot formati icin taslak tanimlari icerir.
//! Tam implementasyon Faz 1 kapsaminda tamamlanacak.

use zeroize::ZeroizeOnDrop;

/// Master key (256 bit AES-XTS icin 512 bit = 2x 256 bit; buraya 64 bayt).
#[derive(ZeroizeOnDrop)]
pub struct MasterKey([u8; 64]);

impl MasterKey {
    /// Yeni bir sifirlanmis master key olusturur.
    pub fn zeroed() -> Self {
        MasterKey([0u8; 64])
    }

    /// Ham baytlara erisim (yalnizca kripto katmani kullanmali).
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Ham baytlara degistirilebilir erisim.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 64] {
        &mut self.0
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}

/// Volume ozellikleri bit bayraklari.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u32);

impl Flags {
    /// Gizli volume iceriyor (outer/inner cifte volume).
    pub const HIDDEN: Flags = Flags(1 << 0);
    /// Sistem volume'u (pre-boot sifreleme).
    pub const SYSTEM: Flags = Flags(1 << 1);
    /// XChaCha20-Poly1305 metadata blogu iceriyor.
    pub const HAS_METADATA: Flags = Flags(1 << 2);

    /// Bayrak seti mi?
    pub fn contains(self, other: Flags) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Volume sektör boyutu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorSize {
    /// 512 bayt (standart HDD/MBR uyumu).
    S512,
    /// 4096 bayt (4Kn Advanced Format sürücüler).
    S4096,
}

impl SectorSize {
    /// Bayt cinsinden deger.
    pub fn as_bytes(self) -> usize {
        match self {
            SectorSize::S512 => 512,
            SectorSize::S4096 => 4096,
        }
    }

    /// Ham u16 degerden donusum; hatali deger icin `None`.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            512 => Some(SectorSize::S512),
            4096 => Some(SectorSize::S4096),
            _ => None,
        }
    }
}

/// Volume header'i acarken gerekli parametreler.
#[derive(Debug)]
pub struct NewVolumeParams {
    /// Volume boyutu (bayt cinsinden; sektör hizali olmali).
    pub volume_size: u64,
    /// Sektör boyutu.
    pub sector_size: SectorSize,
    /// Volume bayraklari.
    pub flags: Flags,
}

/// Cozulmus volume header; turetilmis anahtar ve metadata icerir.
///
/// Tam implementasyon Faz 1'de yapilacak; simdilik taslak.
#[derive(Debug)]
pub struct VolumeHeader {
    /// Master key (AES-XTS icin 512 bit).
    pub master_key: MasterKey,
    /// Volume bayraklari.
    pub flags: Flags,
    /// Sektör boyutu.
    pub sector_size: SectorSize,
    /// Veri alaninın baslangic ofseti (bayt).
    pub data_offset: u64,
    /// Veri alani boyutu (bayt).
    pub data_size: u64,
}
