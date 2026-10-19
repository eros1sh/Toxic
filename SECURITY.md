# Güvenlik Politikası

## Desteklenen Sürümler

| Sürüm   | Güvenlik Desteği |
| ------- | ---------------- |
| 0.x     | Geliştirme aşaması — destek yok |
| 1.0.0+  | Aktif destek |

Proje henüz 1.0.0 sürümüne ulaşmadığı için tüm sürümler geliştirme aşamasındadır. Üretim ortamında kullanım tavsiye edilmez.

## Güvenlik Açığı Bildirimi

**Güvenlik açıklarını herkese açık GitHub issue olarak bildirme.**

### Özel Bildirim Kanalları

E-posta yoluyla bildir. Bildirim e-postasına şunları ekle:

- Güvenlik açığının kısa açıklaması
- Etkilenen bileşen(ler) ve sürüm(ler)
- Yeniden üretme adımları
- Beklenen ve gerçek davranış
- Olası saldırı senaryosu
- Etkisi ve şiddet tahminin (CVSS skoru)
- Varsa kavram kanıtı kodu

### Yanıt Takvimi

| Süreç                          | Hedef Süre |
| ------------------------------ | ---------- |
| İlk onay                       | 48 saat    |
| Şiddet değerlendirmesi         | 5 iş günü  |
| Düzeltme tahmini               | 30 gün     |
| Koordineli açıklama            | 90 gün     |

### Kapsam Dışı

Aşağıdakiler güvenlik açığı sayılmaz:

- Sosyal mühendislik saldırıları
- Fiziksel erişim gerektiren saldırılar (kötü hizmetçi saldırısı dışında — bu kapsam dahilindedir)
- Kullanıcının kasıtlı olarak yanlış yapılandırması
- Tarayıcı eklentileri veya üçüncü taraf yazılım zafiyetleri
- Kullanıcının zaten yönetici erişimine sahip olduğu senaryolar

## Güvenlik Modeli

Toxic, aşağıdaki tehdit modelini temel alır:

### Koruma Altındakiler

- Şifreli volume içeriği (anahtarsız erişime karşı)
- Master key (bellek dökümü ve kernel hata ayıklamaya karşı)
- Pre-boot ortamı (bootkit ve cold-boot saldırılarına karşı)
- Uygulama kilit bütünlüğü (kullanıcı modu atlatma girişimlerine karşı)

### Kapsam Dışı Tehditler

- Doğrudan DMA erişimi olan fiziksel saldırganlar
- Uzlaşmış işletim sistemi çekirdeği (rootkit)
- Tedarik zinciri saldırıları (donanım implantları)
- Kullanıcının sistemi şifre çözüldükten sonra gözetim altına alınması

Ayrıntılı tehdit modeli için bkz. [docs/threat-model.md](docs/threat-model.md).

## Güvenlik Kararları

Temel güvenlik kararları [docs/architecture.md](docs/architecture.md) dosyasındaki ADR'lerde (Mimari Karar Kayıtları) belgelenmiştir:

- ADR-001: Şifre Bileşimi — AES-256-XTS + XChaCha20-Poly1305 + Argon2id
- ADR-003: Çok-Slot Format — 8 AEAD slotu ile paylaşımlı bölge tuzu
- ADR-004: İki Faktör Sınıfı — DerivationFactor vs QuickUnlockFactor
- ADR-006: Kernel Tasarımı — NonPagedPoolNx, güvenli anahtar temizleme
- ADR-007: Pre-Boot El Sıkışması — EfiReservedMemoryType, CRC32C doğrulaması

## Güvenli Geliştirme Uygulamaları

Bu projedeki tüm katkıcılar şunları sağlamalı:

- Cryptographic API doğrulaması için güvenilir kütüphaneler (RustCrypto ekosistemi)
- Sabit zamanlı karşılaştırmalar için `subtle` crate (zamanlama saldırısı önlemi)
- Hassas veriler için `zeroize` ile bellek temizleme
- Tüm hata yollarını kapsayan kapsamlı testler
- Güvenlik açıkları için `cargo-deny` ve `cargo-audit` denetimi

## Teşekkürler

Düzgün şekilde bildirilen güvenlik açıkları için katkıda bulunan araştırmacılar CHANGELOG.md dosyasında (izin verdikleri ölçüde) teşekkürle anılacaktır.
