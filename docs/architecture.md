# Toxic Mimarisi

Durum: **Kararlar alındı, onay bekliyor** · Kapsam: v0.1'den v2.x'e kadar seçilen 225 özellik ve Uygulama Kilidi modülü

Bu belge Toxic'in kalıcı mimari kararlarını tanımlar. Amaç, ilk günden doğru sınırları çizerek 200'den fazla
özelliğin sonradan yeniden yazım gerektirmeden eklenebilmesidir. Her karar bir ADR (Architecture Decision Record)
olarak yazılmıştır; bir karar değişirse ADR'si "Yerine geçti" olarak işaretlenir, silinmez.

---

## 1. Hedefler ve kısıtlar

| Öncelik | Hedef |
|---|---|
| 1 | **Güvenlik**: Anahtar materyali en az bileşende, en kısa süre bulunur. Her bileşen yalnızca ihtiyacı kadar yetkiye sahiptir. |
| 2 | **Doğruluk**: Disk formatı tek bir referans implementasyonda tanımlanır; bootloader, kernel ve servis aynı kodu kullanır. |
| 3 | **Genişletilebilirlik**: Yeni şifre algoritması, yeni kimlik doğrulama faktörü veya yeni platform, format sürümünü kırmadan eklenebilir. |
| 4 | **Denetlenebilirlik**: Tamamen açık kaynak; tekrarlanabilir derleme; her güvenlik iddiası bir testle kanıtlanır. |
| 5 | **Kullanılabilirlik**: Yeni başlayan kullanıcı sihirbazla, uzman kullanıcı CLI ile her şeyi yapabilir. |

Kısıtlar:

- Hedef platform Windows 10 22H2+ ve Windows 11, x64 (ARM64 Faz 9). Linux/macOS yalnızca Ar-Ge.
- Kernel bileşenleri test-signing ile geliştirilir. Resmi dağıtım için Microsoft attestation imzası gerekir (Faz 8).
- Ağ erişimi yalnızca açıkça seçilen özelliklerde vardır (güncelleme denetimi, bulut senkronu). Çekirdek ve servis
  varsayılan olarak hiçbir ağ çağrısı yapmaz (F-160).

---

## 2. Bileşenler ve güven sınırları

```
                          ┌──────────────────────────────────────────┐
  Kullanıcı oturumu       │  Toxic.App (C# / WinUI 3)                │  Orta bütünlük seviyesi, anahtar görmez
  (standart yetki)        │  toxic.exe (Rust CLI)                    │  Parolayı toplar, servise iletir
                          └───────────────┬──────────────────────────┘
                                          │  ① Named pipe  \\.\pipe\toxic.v1
                                          │     ACL: oturum sahibi + SYSTEM, protobuf, boyut limitli
                          ┌───────────────▼──────────────────────────┐
  SYSTEM                  │  ToxicSvc (Rust, Windows servisi)        │  Politika uygulama noktası
                          │   KDF · header işlemleri · mount yönetimi│  Anahtarlar kilitli bellekte, kısa ömürlü
                          │   uygulama kilidi kararları · denetim log│
                          └───────────────┬──────────────────────────┘
                                          │  ② DeviceIoControl (METHOD_BUFFERED)
                                          │     cihaz ACL'i: yalnızca SYSTEM
  Kernel (Ring 0)  ┌──────────────┬───────▼────────┬────────────────┬─────────────────┐
                   │ toxicdisk.sys│ toxicflt.sys   │ toxicguard.sys │ toxicvault.sys  │
                   │ Storport     │ disk alt filter│ süreç/registry/│ minifilter      │
                   │ sanal miniport│ bölüm + sistem│ nesne callback │ (Faz 11)        │
                   │ (container)  │ boot-start     │ (App Lock, öz-koruma)            │
                   └──────────────┴───────▲────────┴────────────────┴─────────────────┘
                                          │  ③ UEFI değişkeni + rezerve bellek (yalnızca açılışta)
  Firmware (pre-boot)      ┌──────────────┴───────────────────────────┐
                           │  ToxicBoot.efi (Rust, no_std)            │
                           │  parola ekranı · header açma · BlockIo   │
                           └──────────────────────────────────────────┘
```

### 2.1 Bileşen sorumlulukları

| Bileşen | Dil | Çalıştığı yer | Sorumluluk | Asla yapmaz |
|---|---|---|---|---|
| `toxic-core` | Rust `no_std` | Her yerde (kütüphane) | Format, KDF, slot açma/kapama, şifre paketleri | I/O, ağ, global durum |
| `toxic-cipher` | Rust `no_std`, `no_alloc` | Kernel (staticlib), UEFI, servis | Sektör şifreleme algoritmaları (XTS, kaskad) | Bellek ayırma, panik |
| `ToxicSvc` | Rust | SYSTEM servisi | Tek yetkili ara katman: KDF, mount, politika, denetim kaydı | GUI çizmek, ağ (izin yoksa) |
| `toxic` CLI | Rust | Kullanıcı | Servise istemci; çevrimdışı araçlar (benchmark, keyfile üretimi) | Driver'a doğrudan erişim |
| `Toxic.App` | C# WinUI 3 | Kullanıcı | Arayüz, sihirbazlar, tepsi, bildirimler | Anahtar türetme, driver erişimi |
| `toxicdisk.sys` | C++ (WDK) + `toxic-cipher` | Kernel | Container'ları disk olarak sunar | Header ayrıştırma, parola görme |
| `toxicflt.sys` | C++ (WDK) + `toxic-cipher` | Kernel, boot-start | Bölüm ve sistem diski I/O şifreleme, hibernate/dump filtresi | Header ayrıştırma |
| `toxicguard.sys` | C++ (WDK) | Kernel | Süreç başlatma kapısı (App Lock), servis ve config öz-koruması | Kimlik doğrulama (karar servistedir) |
| `toxicvault.sys` | C++ (WDK) | Kernel | Dosya bazlı vault (Faz 11) | — |
| `ToxicBoot.efi` | Rust `no_std` | UEFI | Pre-boot kimlik doğrulama, açılış boyunca disk çözme | Windows çalışırken var olmak |

### 2.2 Güven sınırları ve tehditler

| Sınır | Saldırgan | Kontrol |
|---|---|---|
| ① GUI/CLI → Servis | Aynı kullanıcı oturumundaki zararlı yazılım | Pipe ACL'i, `GetNamedPipeClientProcessId` ile istemci oturum doğrulaması, her mesajda şema + boyut doğrulaması, hız sınırı. Kullanıcı oturumunu ele geçiren zararlı yazılım parolayı klavyeden çalabilir; bu kalıntı risktir (bkz. F-173 güvenli masaüstü). |
| ② Servis → Driver | Yönetici olmayan her süreç | Cihaz nesneleri `SDDL: D:P(A;;GA;;;SY)` ile yalnızca SYSTEM'e açık (F-136). IOCTL girişleri kernel'de yeniden doğrulanır; servise güvenilmez. |
| ③ Bootloader → Kernel | Fiziksel erişimli saldırgan (evil-maid) | Anahtar tek kullanımlık rezerve bellekte, CRC ile; driver kopyalayıp sıfırlar. Bootloader bütünlüğü Faz 4'te hash, Faz 8'de TPM ölçümüyle doğrulanır. |
| Disk | Diski çalan saldırgan | Formatın rastgeleden ayırt edilemezliği, Argon2id, AEAD. |

Ayrıntılı STRIDE analizi: `docs/threat-model.md` (Faz 0, F-295).

---

## 3. Depo düzeni (monorepo)

```
toxic/
├── crates/
│   ├── toxic-core/        # Format, slotlar, KDF, faktörler (no_std + alloc)
│   ├── toxic-cipher/      # Şifre paketleri (no_std, no_alloc, panik yok) → staticlib + rlib
│   ├── toxic-ioctl/       # Servis ↔ driver sözleşmesi; cbindgen ile C başlığı üretir
│   ├── toxic-ipc/         # GUI/CLI ↔ servis protokolü (prost, proto/'dan üretilir)
│   ├── toxic-svc/         # Windows servisi
│   ├── toxic-cli/         # toxic.exe
│   ├── toxic-boot/        # ToxicBoot.efi
│   ├── toxic-factors/     # YubiKey, FIDO2, TPM, Hello, PIV, PKCS#11 sağlayıcıları (Faz 4+)
│   └── toxic-applock/     # Uygulama kilidi politika motoru (Faz 5)
├── driver/
│   ├── common/            # Ortak C++ yardımcıları, üretilmiş toxic_ioctl.h
│   ├── toxicdisk/         # Storport sanal miniport
│   ├── toxicflt/          # Disk alt filtresi + dump filtresi
│   ├── toxicguard/        # Süreç/registry/nesne callback'leri
│   └── toxicvault/        # Minifilter (Faz 11)
├── gui/
│   ├── Toxic.App/         # WinUI 3 uygulaması (MVVM)
│   ├── Toxic.Ipc/         # proto/'dan üretilen C# istemcisi
│   └── Toxic.App.Tests/
├── proto/toxic/ipc/v1/    # Protokol tanımları (tek doğruluk kaynağı)
├── installer/             # WiX v5 MSI, driver kurulum betikleri
├── docs/
│   ├── spec/              # Disk formatı, IPC protokolü, pre-boot el sıkışması
│   ├── adr/               # Bu belgedeki kararların ayrıntılı kayıtları
│   ├── threat-model.md
│   └── ROADMAP.md
├── tests/vm/              # Hyper-V tabanlı entegrasyon testleri
├── tools/                 # brand/, sign/, vm/, release/
└── assets/brand/
```

Bağımlılık yönü tek yönlüdür ve CI'da denetlenir:

```
toxic-cipher  ←  toxic-core  ←  toxic-factors  ←  toxic-svc
      ↑               ↑                                ↑
  driver/*        toxic-boot                    toxic-cli, Toxic.App (yalnızca IPC üzerinden)
```

`toxic-core` hiçbir zaman işletim sistemi API'sine bağımlı olmaz. `toxic-cipher` hiçbir zaman bellek ayırmaz.

---

## 4. Kararlar (ADR özeti)

### ADR-001 · Diller

| Katman | Dil | Gerekçe |
|---|---|---|
| Kripto, format, bootloader, servis, CLI | Rust (1.93, pinned) | Bellek güvenliği; aynı kod UEFI, kernel ve user-mode'da derlenir |
| Kernel driver'ları | C++20 (WDK, KMDF/Storport) | Olgun araç zinciri, WinDbg, Microsoft örnekleri |
| Kernel içindeki şifreleme | Rust `toxic-cipher` staticlib | Tek implementasyon; bootloader ile kernel'in aynı baytı üretmesi garanti |
| Arayüz | C# 13 / .NET 9 / WinUI 3 | Windows 11 tasarım dili, erişilebilirlik, Explorer entegrasyonu |

Kernel'de Rust kullanımı kuralları: `toxic-cipher` panik üretemez (`clippy::panic`, `unwrap_used`,
`indexing_slicing`, `arithmetic_side_effects` = deny), bellek ayırmaz, kayan nokta kullanmaz. Panik işleyicisi
yine de tanımlıdır ve `KeBugCheckEx(TOXIC_CIPHER_PANIC)` çağırır: yanlış şifreli veri yazmaktansa sistemi durdurmak
daha güvenlidir. AES-NI (XMM) x64 kernel'de kullanılabilir; VAES/AVX-512 yolları
`KeSaveExtendedProcessorState` ile sarılır.

### ADR-002 · Süreç modeli

- **Servis tek yetkili ara katmandır.** GUI ve CLI driver'a asla doğrudan konuşmaz. Bu, tüm politika
  kontrollerinin (deneme gecikmesi, App Lock kuralları, denetim kaydı) tek yerde olmasını sağlar.
- **Parola yaşam döngüsü:** GUI parolayı `SecureString` yerine sabitlenmiş (`GCHandle.Pinned`) ve kullanım sonrası
  sıfırlanan bir `byte[]` olarak tutar → pipe'a yazar → sıfırlar. Servis `Zeroizing` tamponda alır, KDF'den sonra
  siler. Kernel parolayı hiç görmez, yalnızca master key'i görür.
- **Servis çökerse** bağlı volume'lar çalışmaya devam eder (anahtar kernel'dedir); servis yeniden başladığında
  driver'dan bağlı volume listesini ister.

### ADR-003 · Disk formatı v1: anahtar slotları + metadata bloğu

Mevcut taslak (`docs/spec/header-format.md`) tek slotluydu. Seçilen özellikler (çoklu parola F-059, kurtarma
anahtarı F-224, PQ kurtarma F-026, yerinde şifreleme ilerlemesi F-103, master key rotasyonu F-014) tek slotla
yapılamaz. Onay sonrası format şu yapıya güncellenir:

```
Header bölgesi (64 KiB, rastgeleden ayırt edilemez)
├── region_salt        32 B   Argon2id salt'ı; bölgedeki TÜM slotlarca paylaşılır
├── slot[0..8]         8 × 4 KiB
│     ├── nonce        24 B
│     ├── kem_ct       0 / 1600 B  (yalnızca PQ slotlarında: ML-KEM-1024 + X25519)
│     ├── wrapped      128 B  AEAD(master_key ‖ slot_id ‖ volume_id ‖ slot_flags)
│     ├── tag          16 B
│     └── padding      rastgele
├── metadata           AEAD(metadata_key, VolumeMetadata 1 KiB), metadata_key = HKDF(master_key, "toxic-meta-v1")
└── padding            rastgele
```

Sonuçları:

- **Tek Argon2id, çok slot:** Paylaşılan salt sayesinde bir parola denemesi tek Argon2id çalıştırır, sonra 8
  slotu ucuz AEAD denemeleriyle dener. Çoklu parola desteği kilit açma süresini artırmaz.
- **Metadata herhangi bir slotla güncellenebilir:** İlerleme, bayraklar, cipher bilgisi metadata bloğundadır ve
  master key'den türetilen anahtarla şifrelidir. Bir kullanıcının parolası diğer slotları yeniden yazmayı
  gerektirmez.
- **İnkâr edilebilirlik sınıfları:** Simetrik slotlar (parola, keyfile, YubiKey, FIDO2) rastgeleden ayırt
  edilemez. PQ slotlarının (ML-KEM şifreli metni) istatistiksel ayırt edilemezliği kanıtlanmış değildir; bu
  yüzden PQ slotu eklemek arayüzde "inkâr edilebilirliği zayıflatır" uyarısıyla yapılır.
- **Cipher agility (F-013):** `VolumeMetadata.cipher_suite` alanı (1 = AES-256-XTS, 2 = Serpent, 3 = Twofish,
  10+ = kaskadlar). Master key 512 bayta kadar genişler (üçlü kaskad için 3 × 64 B).

### ADR-004 · Kimlik doğrulama faktörleri

Faktörler iki sınıfa ayrılır ve bu ayrım kod düzeyinde bir trait ile zorunlu kılınır:

| Sınıf | Nasıl çalışır | Diskte iz | Örnekler |
|---|---|---|---|
| **Türetme faktörü** (`DerivationFactor`) | Deterministik bir sır üretir; Argon2id'nin `secret` girdisine karışır | Yok | Parola, keyfile, YubiKey HMAC (challenge = region_salt), FIDO2 hmac-secret (salt = region_salt, discoverable credential), PIV imzası, NFC |
| **Hızlı açma faktörü** (`QuickUnlockFactor`) | Volume dışında, yerel korumalı depoda master key'in sarılmış kopyasını açar | Volume dışında, `%ProgramData%\Toxic\quick\` | TPM 2.0 mühürleme, Windows Hello, TPM+PIN |

Hızlı açma her zaman isteğe bağlıdır ve volume'un kendisini değiştirmez. Kullanıcı hızlı açmayı iptal
ettiğinde yalnızca yerel blob silinir.

### ADR-005 · IPC protokolü

- Taşıma: `\\.\pipe\toxic.v1`, mesaj modu, `PIPE_REJECT_REMOTE_CLIENTS`.
- Çerçeve: `u32` uzunluk + protobuf mesajı, en fazla 64 KiB.
- Şema: `proto/toxic/ipc/v1/*.proto`. Rust tarafı `prost`, C# tarafı `Google.Protobuf` ile üretilir; elle
  yazılmış serileştirme yoktur.
- Sürümleme: paket adı `toxic.ipc.v1`; kırıcı değişiklik yeni bir `v2` paketiyle yapılır, servis iki sürümü
  geçiş süresince birlikte sunar.
- Hassas alanlar (`password`, `keyfile_digest`) ayrı mesaj tiplerindedir ve loglanmaz (log katmanında tip
  bazlı redaksiyon).

### ADR-006 · Kernel tasarımı

- **Container'lar (toxicdisk):** Storport sanal miniport. Windows'a gerçek bir SCSI diski sunar; bölümleme,
  biçimlendirme, Mount Manager, sürücü harfi ve klasöre mount (F-083) Windows'un kendi yığınıyla çalışır. Container
  dosyasına okuma/yazma, servisin açtığı dosya tutamacı üzerinden değil, kernel'in kendi `ZwCreateFile`
  tutamacıyla yapılır (servis çökse de I/O devam eder).
- **Bölüm ve sistem (toxicflt):** Disk sınıfı alt filtresi; `IRP_MJ_READ/WRITE`'ı fiziksel sektör düzeyinde
  şifreler. Boot-start olarak yüklenir; hibernate ve crash dump yazımları için dump filtresi olarak da
  kaydolur (F-116, F-117).
- **Anahtar saklama (F-126):** `NonPagedPoolNx`, dismount'ta `RtlSecureZeroMemory`. Faz 8+'da isteğe bağlı VBS
  enclave (F-140, Ar-Ge).
- **Paralellik (F-124, F-125):** I/O başına bir iş öğesi; CPU sayısı kadar çalışan; sıralama Storport kuyruğuna
  bırakılır.
- **Doğrulama (F-130):** Tüm driver'lar CI ve VM testlerinde Driver Verifier (standart + I/O doğrulama) ile koşar.

### ADR-007 · Pre-boot el sıkışması

1. `ToxicBoot.efi` parolayı alır, `toxic-core` ile sistem volume'unun header'ını açar.
2. `EFI_BLOCK_IO_PROTOCOL`'ü sarar: Windows Boot Manager ve winload şifreli diski okurken sektörler şeffafça
   çözülür.
3. Master key, `EfiReservedMemoryType` tipinde ayrılmış tek sayfaya `{magic, sürüm, anahtar, CRC32C}` olarak
   yazılır; fiziksel adres geçici (non-volatile olmayan) bir UEFI değişkenine konur.
4. `bootmgfw.efi` zincirlenir. `toxicflt.sys` boot-start aşamasında değişkeni okur, sayfayı eşler, anahtarı
   kopyalar, sayfayı sıfırlar ve değişkeni siler.
5. Bu el sıkışma `docs/spec/preboot-handoff.md` ile ayrıca belgelenir ve VM testleriyle doğrulanır.

### ADR-008 · Arayüz

- WinUI 3 + Windows App SDK, MVVM (`CommunityToolkit.Mvvm`), DI (`Microsoft.Extensions.Hosting`).
- Explorer sağ tık menüsü (F-248) `IExplorerCommand` ile; bunun için uygulama "external location" ile paketlenir
  (sparse package).
- Yerelleştirme `.resw` dosyalarıyla Türkçe ve İngilizce (F-243); tüm metinler kaynak dosyalarındadır.
- Arayüz servise yalnızca `Toxic.Ipc` üzerinden konuşur; servis yoksa salt "servis çalışmıyor" ekranı gösterir.

### ADR-009 · Yapılandırma ve durum

| Veri | Konum | Koruma |
|---|---|---|
| Servis yapılandırması (TOML) | `%ProgramData%\Toxic\config.toml` | ACL: SYSTEM + Administrators yazabilir; şema doğrulaması |
| App Lock kuralları | `%ProgramData%\Toxic\applock.toml` | Aynı ACL + `toxicguard` registry/dosya koruması |
| Hızlı açma blob'ları | `%ProgramData%\Toxic\quick\` | TPM/DPAPI ile sarılı, ACL: yalnızca SYSTEM |
| Kullanıcı tercihleri | `%LocalAppData%\Toxic\` | Sır içermez |
| Denetim kaydı | `%ProgramData%\Toxic\audit\` | Hash zinciri (F-189, App Lock) |

Toxic varsayılan olarak mount geçmişi tutmaz; denetim kaydı yalnızca kullanıcı açarsa yazılır (F-160 ile uyumlu).

### ADR-010 · Tedarik zinciri ve sürümler

- Rust toolchain ve .NET SDK sürümleri sabitlenir; `Cargo.lock` ve `packages.lock.json` depoya girer.
- `cargo-deny` (lisans + güvenlik açığı + kaynak denetimi), `cargo-audit`, `dotnet list package --vulnerable` CI'da
  bloklayıcıdır (F-288).
- Sürümler Ed25519 + ML-DSA-65 hibrit imzayla imzalanır (F-024, F-287); güncelleyici iki imzayı da doğrular.
- Hedef: tekrarlanabilir derleme (F-298 ile performans, Ar-Ge ile formel doğrulama).

### ADR-011 · Test stratejisi

| Katman | Araç | Ne kanıtlar |
|---|---|---|
| Birim + test vektörleri | `cargo test`, xUnit | Algoritmalar resmi vektörlerle, format kendi vektörleriyle (F-281) |
| Fuzzing | `cargo-fuzz` | Header, metadata ve IPC ayrıştırıcıları çökmez (F-282) |
| Sabit zaman | dudect | Karşılaştırmalar veri bağımlı süre üretmez |
| Driver | Driver Verifier, HLK alt kümesi | Bellek, IRQL, kilit hataları yok |
| Entegrasyon | Hyper-V Gen2 VM'ler (F-290) | Oluştur → mount → yaz → dismount → yeniden aç döngüsü; sistem şifreleme ve kurtarma |
| Uyumluluk | Test matrisi (F-299) | Windows 10/11, farklı firmware, BitLocker'lı/BitLocker'sız |

### ADR-012 · Lisans ve yönetişim

**Karar: MIT.** Proje ilk commit'ten itibaren açık kaynaktır; lisans Faz 0'da uygulanır (F-293 v1'den Faz 0'a
çekildi). WinLock da MIT olduğu için iki proje arasında kod serbestçe taşınabilir.

Bilinen sonuçları: MIT kapalı kaynak türevlere izin verir ve açık bir patent hükmü içermez. Bağımlılıklar yalnızca
MIT ile uyumlu lisanslardan seçilir (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode); `cargo-deny` GPL/LGPL/AGPL
bağımlılıkları reddeder.

Kurallar: DCO (`Signed-off-by`) zorunlu; `SECURITY.md` ile özel güvenlik bildirimi kanalı; TrueCrypt lisanslı kod
**asla** kopyalanmaz. VeraCrypt/TrueCrypt uyumluluğu (F-017, F-018) yalnızca belgelenmiş formata göre sıfırdan yazılır.

### ADR-013 · Uygulama Kilidi (WinLock entegrasyonu)

WinLock'un IFEO + ETW yaklaşımı user-mode'da çalışır ve kendi README'sinde belirtildiği gibi kernel callback'i
"imzalı driver gerektirdiği için" kapsam dışıdır. Toxic'te driver zaten olduğundan kilit kernel'de uygulanır:

1. `toxicguard.sys`, `PsSetCreateProcessNotifyRoutineEx2` ile her süreç oluşturmayı görür.
2. Korunan bir imaj başlatılırsa (eşleşme: Authenticode yayıncısı + SHA-256 + yol; yalnızca dosya adına bakılmaz,
   böylece kopyalayıp adını değiştirerek atlatma önlenir) ve geçerli bir oturum izni yoksa
   `CreationStatus = STATUS_ACCESS_DENIED` ile engellenir ve servise bir olay gönderilir.
3. Servis, kullanıcının oturumunda Toxic kimlik doğrulama penceresini açar (aynı faktörler: parola, Hello,
   FIDO2, TOTP).
4. Başarılı doğrulamada servis driver'a o imaj için süreli izin yazar ve süreci orijinal komut satırı, çalışma
   dizini ve kullanıcı token'ıyla yeniden başlatır.
5. **Toxic'e özgü fark:** Bir uygulama bir Toxic volume'una bağlanabilir. Örneğin tarayıcı profili şifreli bir
   container'dadır; kilit açılınca volume otomatik mount edilir, uygulama kapanınca dismount edilir. Kilit atlatılsa
   bile veri şifreli kalır.
6. Driver yüklenemeyen sistemler için WinLock'un IFEO + ETW yöntemi "uyumluluk modu" olarak taşınır (daha zayıf
   olduğu arayüzde açıkça yazılır).

WinLock ve Toxic aynı lisansı (MIT) kullandığı için tasarım ve kod parçaları serbestçe taşınabilir; kod Go'dan
Rust'a yeniden yazılır.

---

## 5. Sürüm ve faz eşlemesi

| Sürüm | Fazlar | İçerik |
|---|---|---|
| v0.1-alpha | Faz 0-1 | Altyapı, format, kripto çekirdeği, CLI ile container oluşturma/doğrulama |
| v0.2-alpha | Faz 2 | Driver + servis: container'ı CLI ile mount etme |
| **v0.3 (MVP)** | Faz 3 | Arayüz, kurulum paketi |
| v0.4 | Faz 4 | Bölüm şifreleme, kurtarma, donanım anahtarları, acil durum |
| v0.5 | Faz 5 | Uygulama Kilidi |
| **v1.0** | Faz 6 | Sistem şifreleme (ToxicBoot) |
| v1.1-v1.4 | Faz 7-10 | Algoritmalar, TPM ve gelişmiş açılış, sertleştirme, kuantum sonrası |
| v2.0-v2.1 | Faz 11-12 | Vault ve bulut, otomasyon |
| Sürekli | Ar-Ge hattı | Fizibilite çalışmaları; olumlu sonuçlananlar bir faza alınır |

Özellik bazında ayrıntılar: `docs/ROADMAP.md`.
