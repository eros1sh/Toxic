//! Volume fiziksel düzeni: header ofseti, veri alani, bölge tuzlari.
//!
//! ADR-003: Layout A (konteyner / ayri bolum) ve Layout B (yerinde sifreleme) desteklenir.
//! Tam implementasyon Faz 1 ve Faz 4 kapsaminda tamamlanacak.

use crate::{Error, Result, SALT_LEN};

/// Minimum veri alani boyutu (en az 1 MB).
pub const MIN_DATA_SIZE: u64 = 1 << 20; // 1 MiB

/// ADR-003 header bolgesi boyutu: 8 slot x 4 KiB + metadata blogu + tuzlar.
/// Toplam: 32 (region_salt) + 8 * 4096 (slotlar) + 4096 (metadata) = 36896 bayt.
/// Pratik deger: bir sektore hizali olmasi icin 65536 (64 KiB) kullanilir.
pub const HEADER_REGION_SIZE: u64 = 65_536;

/// Volume düzeni tipleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// Layout A: Header volume/konteyner basinda, yedek header sonda.
    /// Konteyner dosyalari ve ayri bolum sifrelemesi icin kullanilir.
    Standard,
    /// Layout B: Header volume sonunda (yerinde sifreleme icin).
    /// Faz 4 sistem sifrelemesinde kullanilir.
    InPlace,
}

/// Hesaplanmis volume düzeni.
#[derive(Debug, Clone, Copy)]
pub struct VolumeLayout {
    /// Birincil header bolgesinin baslangic ofseti (bayt).
    pub primary_header_offset: u64,
    /// Yedek header bolgesinin baslangic ofseti (bayt); Layout B'de None.
    pub backup_header_offset: Option<u64>,
    /// Veri alaninın baslangic ofseti (bayt).
    pub data_offset: u64,
    /// Veri alani boyutu (bayt).
    pub data_size: u64,
}

impl VolumeLayout {
    /// Verilen toplam boyut ve duzen icin layout hesaplar.
    ///
    /// # Hatalar
    /// - `InvalidLayout`: toplam boyut cok kucuk veya sektör hizali degil.
    pub fn compute(
        total_size: u64,
        sector_size: u64,
        kind: LayoutKind,
    ) -> Result<Self> {
        // Sektör boyutu 512 veya 4096 olmali.
        if sector_size != 512 && sector_size != 4096 {
            return Err(Error::InvalidSectorSize);
        }

        match kind {
            LayoutKind::Standard => {
                // Layout A: primary_header | data | backup_header
                let data_offset = HEADER_REGION_SIZE;
                let backup_size = HEADER_REGION_SIZE;

                if total_size < data_offset + MIN_DATA_SIZE + backup_size {
                    return Err(Error::InvalidLayout);
                }

                let data_size = total_size - data_offset - backup_size;
                // Veri alani sektör hizali olmali.
                let data_size = data_size - (data_size % sector_size);

                if data_size < MIN_DATA_SIZE {
                    return Err(Error::InvalidLayout);
                }

                Ok(VolumeLayout {
                    primary_header_offset: 0,
                    backup_header_offset: Some(data_offset + data_size),
                    data_offset,
                    data_size,
                })
            }
            LayoutKind::InPlace => {
                // Layout B: data | header (sonda)
                let header_at_end_offset = total_size
                    .checked_sub(HEADER_REGION_SIZE)
                    .ok_or(Error::InvalidLayout)?;

                let data_size = header_at_end_offset;
                let data_size = data_size - (data_size % sector_size);

                if data_size < MIN_DATA_SIZE {
                    return Err(Error::InvalidLayout);
                }

                Ok(VolumeLayout {
                    primary_header_offset: header_at_end_offset,
                    backup_header_offset: None,
                    data_offset: 0,
                    data_size,
                })
            }
        }
    }
}

/// Bolge tuzu (region_salt): ADR-003 cok-slot formati icin paylasilan Argon2id tuzu.
#[derive(Clone)]
pub struct RegionSalt([u8; SALT_LEN]);

impl RegionSalt {
    /// Ham baytlardan olusturur.
    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        RegionSalt(bytes)
    }

    /// Ham baytlara erisim.
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for RegionSalt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Tuz gizli tutulmali; ozet goster.
        write!(f, "RegionSalt([{}...{}])", self.0[0], self.0[31])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_layout_ok() {
        // 100 MiB konteyner.
        let total = 100 * 1024 * 1024u64;
        let layout = VolumeLayout::compute(total, 512, LayoutKind::Standard).unwrap();

        assert_eq!(layout.primary_header_offset, 0);
        assert!(layout.backup_header_offset.is_some());
        assert_eq!(layout.data_offset, HEADER_REGION_SIZE);
        assert!(layout.data_size >= MIN_DATA_SIZE);
        // Boyutlar tutarli olmali.
        assert_eq!(
            layout.data_offset + layout.data_size + HEADER_REGION_SIZE,
            total
        );
    }

    #[test]
    fn standard_layout_too_small() {
        // 1 MiB cok kucuk (iki header + veri sigmaz).
        let result = VolumeLayout::compute(1024 * 1024, 512, LayoutKind::Standard);
        assert!(result.is_err());
    }

    #[test]
    fn inplace_layout_ok() {
        let total = 50 * 1024 * 1024u64;
        let layout = VolumeLayout::compute(total, 512, LayoutKind::InPlace).unwrap();

        assert_eq!(layout.data_offset, 0);
        assert!(layout.backup_header_offset.is_none());
        assert!(layout.data_size >= MIN_DATA_SIZE);
    }
}
