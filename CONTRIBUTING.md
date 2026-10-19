# Katkıda Bulunma Rehberi

Toxic projesine katkıda bulunmak istediğin için teşekkürler. Bu rehber süreci açıklar.

## Davranış Kuralları

Tüm katkıda bulunanlar [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) dosyasındaki kurallara uymayı kabul eder.

## Güvenlik Açıkları

Güvenlik açığı bildirmek için lütfen doğrudan herkese açık bir issue açma. Bunun yerine [SECURITY.md](SECURITY.md) dosyasındaki süreci izle.

## Geliştirme Ortamı

### Ön Gereksinimler

- Rust 1.93.1+ (`rust-toolchain.toml` otomatik olarak sabitler)
- Windows 11 22H2+ (sürücü geliştirmesi için)
- WDK 10.0.26100+ (sürücü crate'leri için)
- Visual Studio 2022 (WDK bağımlılıkları için)
- Python 3.11+ (araçlar ve testler için)

### Kurulum

```bash
# Rust araç zinciri
rustup show  # rust-toolchain.toml dosyasını okur ve gerekirse indirir

# Bağımlılık denetimi
cargo install cargo-deny
cargo deny check

# Derleme
cargo build --workspace

# Testler
cargo test --workspace
```

### Test İmzalama (Kernel Sürücüleri)

Sürücü geliştirmesi için test imzalamasını etkinleştir:

```powershell
# Yönetici PowerShell gerektirir
.\scripts\setup-test-signing.ps1
# Bilgisayarı yeniden başlat
```

## Katkı Türleri

### Hata Düzeltmeleri

1. `fix/issue-NNN-kisa-aciklama` dalı oluştur
2. Hatayı yeniden üreten test yaz
3. Düzeltmeyi uygula
4. Tüm testlerin geçtiğini doğrula
5. Pull Request aç

### Yeni Özellikler

1. Önce bir issue açarak tasarımı tartış
2. [ROADMAP.md](docs/ROADMAP.md) dosyasında ilgili fazı kontrol et
3. `feat/faz-N-ozellik-adi` dalı oluştur
4. Tüm hata yollarını kapsayan testler yaz
5. Yeterli kapsama ulaştıktan sonra PR aç

### Belgeler

Belgeler Türkçe olmalıdır. Kod içi yorumlar Türkçe, değişken/fonksiyon isimleri İngilizce olmalıdır.

## Kod Standartları

### Rust

```bash
# Biçimlendirme (kaydetmeden önce zorunlu)
cargo fmt --all

# Linting (CI bloklayan)
cargo clippy --all-targets --all-features -- -D warnings

# Güvenlik denetimi
cargo deny check
```

### Kural Listesi

- `#![forbid(unsafe_code)]` tüm kullanıcı alanı crate'lerinde zorunludur
- Kernel sürücüleri (C++) için RAII, smart pointer, sanitizer
- Hata türleri `non_exhaustive` olarak işaretlenmeli
- Public API değişiklikleri CHANGELOG.md güncellemesi gerektirir
- Parolalar ve anahtarlar bellekte `zeroize` ile sıfırlanmalı
- Yorumlar Türkçe, değişkenler/fonksiyonlar İngilizce

### Commit Mesajları

```
<tip>(<kapsam>): <kısa açıklama>

<uzun açıklama (isteğe bağlı)>

<issue referansı (isteğe bağlı)>
```

Tipler: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`

Örnek:
```
feat(kdf): Argon2id çok-slot türetme ekle

ADR-003 multi-slot formatı için region_salt paylaşımlı
tek Argon2id türetme + 8 AEAD slot denemesi.

Closes #42
```

## Pull Request Süreci

1. Tüm CI kontrolleri yeşil olmalı
2. En az bir bakıcı onayı gerekli
3. Güvenlik etkisi olan değişiklikler iki bakıcı onayı gerektirir
4. Squash merge kullanılır (dal geçmişini temizler)

## Mimari Kararlar

Önemli tasarım kararları için [docs/architecture.md](docs/architecture.md) dosyasındaki ADR formatını kullan. ADR numarası proje yöneticisi tarafından atanır.

## Lisans

Bu projeye katkıda bulunarak, katkıların MIT Lisansı kapsamında yayımlanacağını kabul etmiş olursun. Ayrıntılar için bkz. [LICENSE](LICENSE).
