# Toxic — Tehdit Modeli

**Sürüm:** 1.0  
**Tarih:** 2026-10  
**Durum:** Taslak

---

## 1. Kapsam

Bu belge Toxic disk şifreleme uygulamasının tehdit modelini tanımlar. STRIDE + kötüye kullanım senaryosu çerçevesine dayanır.

**Kapsam dahilinde:**
- Konteyner dosya şifrelemesi
- Bölüm/disk şifrelemesi
- UEFI pre-boot kimlik doğrulaması (sistem şifrelemesi)
- Uygulama kilidi (App Lock)
- Gizli volume'lar

**Kapsam dışı:**
- Şifre çözüldükten sonra verilerin yetkili kullanıcı tarafından sızdırılması
- Donanım implantı ile gerçekleştirilen tedarik zinciri saldırıları
- DMA erişimi olan doğrudan fiziksel saldırılar (özel donanım)
- Kompromi edilmiş işletim sistemi çekirdeğindeki rootkit (tam kernel rootkit)

---

## 2. Korunan Varlıklar

| Varlık | Gizlilik | Bütünlük | Erişilebilirlik |
|--------|----------|----------|-----------------|
| Volume veri içeriği | Kritik | Kritik | Yüksek |
| Master key (bellek içi) | Kritik | Kritik | Orta |
| Kullanıcı parolası (transit/bellek) | Kritik | Yüksek | Orta |
| Keyfile içeriği | Yüksek | Yüksek | Orta |
| Volume header (disk üzeri) | Yüksek | Kritik | Yüksek |
| Uygulama kilidi kuralları | Orta | Yüksek | Yüksek |
| Pre-boot kimlik doğrulaması | Kritik | Kritik | Kritik |

---

## 3. Güven Sınırları

```
┌─────────────────────────────────────────────────────────────────┐
│                    Fiziksel Saldırgan                           │
│  (Soğuk başlatma, Evil Maid, bellek boşaltma, DMA)             │
└────────────────────────┬────────────────────────────────────────┘
                         │ fiziksel erişim
┌────────────────────────▼────────────────────────────────────────┐
│                   UEFI Ortamı (Ring -1)                         │
│  ToxicBoot.efi ↔ EFI_BLOCK_IO_PROTOCOL ↔ Disk                 │
└────────────────────────┬────────────────────────────────────────┘
                         │ EfiReservedMemoryType sayfa (master key)
┌────────────────────────▼────────────────────────────────────────┐
│                Kernel Modu (Ring 0)                             │
│  toxicdisk.sys │ toxicflt.sys │ toxicguard.sys                 │
│  NonPagedPoolNx bellek │ APC engellemesi                        │
└────────────────────────┬────────────────────────────────────────┘
                         │ IOCTL / DeviceIoControl
┌────────────────────────▼────────────────────────────────────────┐
│              Ayrıcalıklı Kullanıcı Modu (Ring 3)                │
│  toxic-svc.exe (servis) ↔ Named Pipe IPC ↔ toxic-gui.exe       │
│  YubiKey/FIDO2 API │ Windows Hello API │ PIV/PKCS#11            │
└────────────────────────┬────────────────────────────────────────┘
                         │ GUI etkileşimi
┌────────────────────────▼────────────────────────────────────────┐
│                    Kullanıcı                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Saldırı Yüzeyi

| Yüzey | Risk | Azaltma | Durum |
|-------|------|---------|-------|
| Named Pipe IPC | Orta | `PIPE_REJECT_REMOTE_CLIENTS`, mesaj bütünlüğü, servis kimlik doğrulaması | Planlandı |
| IOCTL arayüzü | Yüksek | Kernel tarafı girdi doğrulaması, `ProbeForRead/Write`, tampon boyutu kontrolleri | Planlandı |
| Parola girişi (GUI) | Orta | Güvenli Desktop (`LOGDESKTOP`), bellek sıfırlama (zeroize) | Planlandı |
| Pre-boot parola (UEFI) | Yüksek | Yalnızca yazdırılabilir ASCII, GOP ekranı klavye okunması | Planlandı |
| Keyfile yolu | Düşük | BLAKE2b-256 özeti, dosya uzantısı/içerik doğrulaması yok | Uygulandı |
| Disk üzeri header | Yüksek | AEAD bütünlük doğrulaması, ayırt edilemez şifreli metin | Planlandı |
| App Lock IPC | Orta | Servis kimlik doğrulaması, imzalı kural seti, kernel düzeyi engelleme | Planlandı |
| YubiKey/FIDO2 arayüzü | Orta | HMAC-sırları cihazdan çıkmaz, doğrulama cihaz tarafında | Planlandı |
| TPM PCR doğrulaması | Yüksek | PCR ayarı + TPM2_PolicyPCR, önyükleme ölçümlerine bağlama | Planlandı |

---

## 5. STRIDE Analizi

### 5.1 Kimlik Sahteciliği (Spoofing)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| S-01: JWT/token sahteciliği | IPC üzerinden sahte servis kimliği | Yetkisiz IOCTL | İsimli boru nesnesi güvenlik tanımlayıcısı, oturum izolasyonu |
| S-02: Token tekrar oynatma | Ele geçirilmiş IPC oturumu | Volume açma | Her oturum için rastgele nonce, kısa oturum ömrü |
| S-03: Pre-boot kimlik sahteciliği | ToxicBoot.efi taklit | Master key hırsızlığı | UEFI Güvenli Başlatma + sürücü imzası |
| S-04: YubiKey HMAC taklidi | Yazılım tabanlı HMAC simülasyonu | Yetkisiz açma | Donanım sırları cihazdan çıkmaz, challenge-response protokolü |

### 5.2 Kurcalama (Tampering)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| T-01: Header değiştirilmesi | Şifreli header bitlerini çevirme | Veri kaybı veya AEAD başarısızlığı (tespit edilir) | AEAD bütünlük etiketi — tespit garantili |
| T-02: IPC mesaj değiştirilmesi | Man-in-the-middle named pipe | Kötü amaçlı komutlar | Protobuf şeması doğrulaması, oturum bütünlüğü |
| T-03: Kural seti değiştirilmesi | App Lock kural dosyasını değiştirme | Kural atlatma | Kernel tarafı doğrulama, HMAC imzalı kurallar |
| T-04: Kernel sürücüsü değiştirilmesi | Sürücü dosyasını değiştirme | Tam sistem kompromizi | Code Integrity / WHQL imzası, Güvenli Başlatma |

### 5.3 İnkar Edilemezlik (Repudiation)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| R-01: Denetim günlüğü olmaksızın açma | Volume kayıt yok | Yetkisiz erişim izi bırakmaz | Yapılandırılmış denetim günlüğü (Faz 9) |
| R-02: Kural değişikliği kaydı yok | App Lock kural değişiklikleri | Politika değişikliğinin kimin yaptığı belirsiz | Değişiklik için kimlik doğrulaması + günlük kaydı |

### 5.4 Bilgi İfşası (Information Disclosure)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| I-01: Soğuk başlatma saldırısı | RAM bellek damping | Master key kurtarma | Kapatmada bellek sıfırlama, EfiReservedMemoryType silme |
| I-02: Uyku/hazırda bekletme | Hibernasyon dosyasında master key | Key açık metin | Dump filtresi (toxicflt.sys dumpflt), hibernasyon engelleme seçeneği |
| I-03: Sayfa dosyası sızıntısı | Parola/anahtar sayfa dosyasına sızar | Key materyal açığa çıkar | `MmProbeAndLockPages` + `MdlMappingNoWrite`, NonPagedPool kullanımı |
| I-04: Zamanlama yan kanalı | AES-NI olmayan sistemlerde zamanlama | Kısmi anahtar bilgisi | AES-NI zorunlu; yazılım AES sabit zamanlı RustCrypto ile |
| I-05: Hata mesajı sızıntısı | Ayrıntılı hata kodları | Volume varlığı ortaya çıkar | Kimlik bilgisi hatası tek tip (InvalidCredentials) |
| I-06: Meta veri sızıntısı | Şifreli container boyutu | Volume tahminleri | Header padding, standart container boyutları |

### 5.5 Hizmet Reddi (Denial of Service)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| D-01: KDF DoS | Yoğun Argon2id istekleri | CPU/RAM tüketimi | Hız sınırlama, istek başı oturum |
| D-02: IOCTL flood | Çok sayıda IOCTL isteği | Kernel kaynak tüketimi | IOCTL hız sınırlama, çağıran doğrulaması |
| D-03: Named pipe flood | Pipe bağlantı seli | Servis kullanılamaz | Bağlantı başına kaynak sınırı |
| D-04: Volume kilitlenmesi | Panik kısayolu veya zorla çıkarma | Veri kaybı riski | Temiz bağlantı kesme, yazma tamponu temizleme |
| D-05: Pre-boot kilitlenme | ToxicBoot sonsuz döngü | Açılış yapılamaz | Watchdog zamanlayıcısı, kurtarma USB |

### 5.6 Ayrıcalık Yükseltme (Elevation of Privilege)

| Tehdit | Vektör | Etki | Azaltma |
|--------|--------|------|---------|
| E-01: Kiracılar arası erişim | Bir kullanıcının başka volume'una erişim | Yetkisiz veri okuma | Volume başına erişim denetimi listesi (ACL) |
| E-02: Servis kimliğine bürünme | toxic-svc.exe kimliğine bürünme | Kernel IOCTL erişimi | Minimum ayrıcalık servisi, Named Pipe güvenlik tanımlayıcısı |
| E-03: App Lock atlatma | Kullanıcı modu çekirdeğini aşma | Kilit kuralları ihlal edilir | Kernel düzeyi engelleme (PsSetCreateProcessNotifyRoutineEx2) |
| E-04: Korumasız kernel belleği | NonPagedPool yerine PagedPool | Key bellekten dökülebilir | Tüm key depolama NonPagedPoolNx |

---

## 6. Kötüye Kullanım Senaryoları

### 6.1 Evil Maid Saldırısı

**Senaryo:** Fiziksel erişimi olan saldırgan dizüstü bilgisayarı değiştirir, bootloader'ı değiştirir ve pre-boot parolayı yakalar.

**Azaltma:**
1. UEFI Güvenli Başlatma + ToxicBoot.efi imzası (Microsoft UEFI CA)
2. TPM PCR bağlama (PCR 0-7 + PCR 11 önyükleme ölçümleri)
3. Anti-hammering (hatalı giriş başına bekleme süresi)
4. Fiziksel kurcalama algılama (yazılım seviyesinde mümkün değil; donanım kasası önerilir)

### 6.2 Soğuk Başlatma Saldırısı

**Senaryo:** Saldırgan sistem çalışırken veya kapandıktan hemen sonra RAM'i boşaltır.

**Azaltma:**
1. Sürekli çalışmayan AES anahtarları (`MmSecureVirtualMemory` + `RtlSecureZeroMemory`)
2. Kapatma/uyku/kilitlenme olaylarında master key sıfırlama (PnP bildirim kaydı)
3. Volume'ların uyku öncesi bağlantısı kesilmesi (yapılandırılabilir)
4. EfiReservedMemoryType sayfasını OS ele geçirmeden önce sil

### 6.3 Duress Parolası (F-144)

**Senaryo:** Kullanıcı zorla parola açıklamaya zorlanır.

**Azaltma:**
1. Duress parolası ayrı bir slot açar, sahte veya boş volume gösterir
2. Opsiyonel: master key silme işlemini tetikler (nuclear seçeneği)
3. Gerçek ve tuzak volume birbiriyle istatistiksel olarak ayırt edilemez

### 6.4 Gizli Volume Tespiti

**Senaryo:** Saldırgan outer ve inner volume'un varlığını ispatlayabilir mi?

**Azaltma:**
1. Outer ve inner volume başlıkları şifreli ve rastgele veri ile ayırt edilemez
2. Outer volume yazmaları inner volume üzerindeki padding alanını zorunlu olarak bırakır
3. Header bölgesi tamamen rastgele görünür (şifreli header + rastgele dolgu)

### 6.5 Kernel Sürücüsü Exploit

**Senaryo:** Güvenlik açığı kernel modunda kod yürütülmesine izin verir.

**Azaltma:**
1. Kernel kodu WDK güvenli kodlama yönergeleri ile yazılır
2. IOCTL girdi doğrulaması `ProbeForRead/Write` + boyut kontrolleri
3. HVCI / Memory Integrity uyumlu
4. KernelModeCode WHQL imzalı (Faz 8)

---

## 7. Kalıcı Riskler

| Risk | Kabul Edilen Neden | İzleme |
|------|--------------------|--------|
| Donanım keylogger | Uygulama katmanının dışında | Fiziksel güvenlik tavsiyesi (belge) |
| Kompromi edilmiş UEFI firmware | Yazılım kontrolünün dışında | Secure Boot + TPM PCR bağlama azaltır |
| Kuantum bilgisayar (gelecek) | ML-KEM-1024 (PQ) Faz 10'da eklenir | Kriptografik çeviklik mekanizması mevcut |
| Side-channel (önbellek zamanlaması) | AES-NI ile azaltılmış, sıfırlanamaz | AES-NI zorunlu yapılandırma, uyarı |
| Kötü amaçlı bellek dökümü (VS Debugger) | Geliştirme ortamında kabul edilir | Üretim: Debug portları devre dışı |

---

## 8. Güvenlik Gereksinimleri Özeti

| No | Gereksinim | Bileşen | Öncelik |
|----|-----------|---------|---------|
| SR-01 | Master key yalnızca NonPagedPoolNx bellekte | toxicdisk/toxicflt | Kritik |
| SR-02 | Tüm parola/anahtar materyali düşme anında sıfırlanır | toxic-core | Kritik |
| SR-03 | AEAD doğrulama başarısız olursa İnvalidCredentials dön | toxic-core | Kritik |
| SR-04 | Disk üzeri biçim şifreli metinden volume varlığı çıkarılamaz | toxic-core | Yüksek |
| SR-05 | Pre-boot mesaj yan kanalı yok (zamanlama sabit) | ToxicBoot | Yüksek |
| SR-06 | Named Pipe yalnızca yerel bağlantıları kabul eder | toxic-svc | Yüksek |
| SR-07 | App Lock atlatma için kernel düzeyi engelleme | toxicguard | Yüksek |
| SR-08 | Kurtarma USB olmadan tamamen kilitlenme mümkün değil | ToxicBoot | Orta |
| SR-09 | Dump filtresi hibernasyon sırasında anahtar gizler | toxicflt | Kritik |
| SR-10 | IOCTL arayüzü hız sınırlama uygular | toxicdisk/toxicflt | Orta |

---

## 9. Referanslar

- [STRIDE tehdit modelleme metodolojisi](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [VeraCrypt güvenlik değerlendirmesi (2016, QuarksLab)](https://veracrypt.eu/en/Security%20Requirements%20and%20Precautions.html)
- [NIST SP 800-111: Taşınabilir depolama cihazlarında şifreleme rehberi](https://csrc.nist.gov/publications/detail/sp/800-111/final)
- [ADR-001 — ADR-013: docs/architecture.md](architecture.md)
