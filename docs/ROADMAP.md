# Toxic Yol Haritası

Durum: **Kararlar alındı, faz onayı bekliyor** · 225 seçili özellik + 12 Uygulama Kilidi özelliği · Mimari: [architecture.md](architecture.md)

Her faz, kendinden önceki fazların üzerine kurulur ve sonunda çalışan, test edilmiş bir sürüm çıkarır. Bir faz
bitmeden sonrakine geçilmez; tek istisna, her zaman paralel yürüyen **Ar-Ge hattıdır**.

Bileşen kısaltmaları: **core** `toxic-core` · **cipher** `toxic-cipher` · **svc** ToxicSvc · **cli** toxic.exe ·
**gui** Toxic.App · **disk** toxicdisk.sys · **flt** toxicflt.sys · **guard** toxicguard.sys · **vault**
toxicvault.sys · **boot** ToxicBoot.efi · **infra** CI, kurulum, belgeler

---

## Alınan kararlar

1. **Faz sırası:** Uygulama Kilidi (Faz 5) sistem şifrelemesinden (Faz 6) önce gelir. Gerekçe: sistem
   şifrelemesi en riskli iş; App Lock ise Faz 2-4'te kurulan driver ve servis altyapısını hemen kullanabiliyor.
2. **Lisans:** MIT (bkz. ADR-012). WinLock ile aynı lisans; kod parçaları serbestçe taşınabilir.
3. **Bağımlılık boşluğu kapatıldı:** F-145 (çok katmanlı gizli volume), F-118 (gizli işletim sistemi) ve F-193
   (sahte çökme) için gereken F-142 (gizli volume), F-143 (gizli volume koruması) ve F-144 (baskı parolası)
   listeye eklendi ve Faz 4'e yerleştirildi. Toplam seçili özellik 225.
4. **Fizibilitesi düşük özellikler** Ar-Ge hattında kalır; her biri için fizibilite raporu yazılır, olumsuz
   çıkarsa gerekçesiyle kapatılır:
   - F-073 SGX/SEV: Intel, SGX'i 11. nesilden itibaren tüketici işlemcilerinden kaldırdı; SEV yalnızca sunucu ve
     sanal makine içindir. Masaüstünde karşılığı büyük ihtimalle yok. Yerine F-140 (VBS enclave) öneriliyor.
   - F-166 Anahtarı CPU register'ında tutma: Windows debug register'larını iş parçacığı bağlamında kendisi
     yönetir ve PatchGuard bu alana müdahaleyi engeller. Büyük ihtimalle uygulanamaz.
   - F-029 QKD: Özel kuantum ağ donanımı gerektirir. Çıktısı bir araştırma raporu olur, ürün özelliği değil.
   - F-067 Pre-boot parmak izi: Okuyucuların çoğu üreticiye özel, belgelenmemiş protokol kullanır.
5. **Resmi dağıtım:** Açık kaynak olduğu için başkaları da kullanacak. Test modu gerektirmeyen resmi sürüm için
   EV kod imzalama sertifikası ve Microsoft attestation imzası (F-128) gerekir. O zamana kadar sürümler
   "geliştirici önizlemesi" olarak test modunda çalışır.

---

## Faz 0 · Temeller → v0.0

Amaç: kod yazmadan önce sözleşmeleri, araçları ve güvenlik çerçevesini sabitlemek.

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-293 | Lisans seçimi | MIT `LICENSE`, her kaynak dosyada `SPDX-License-Identifier: MIT`, `CONTRIBUTING.md` (DCO), `SECURITY.md`, `CODE_OF_CONDUCT.md`; `cargo-deny` lisans allowlist'i MIT ile uyumlu lisanslara göre. v1'den öne çekildi. | infra |
| F-295 | Tehdit modeli belgesi | `docs/threat-model.md`: varlıklar, güven sınırları (mimari §2.2), STRIDE tablosu, kalıntı riskler. Her faz sonunda güncellenir. | infra |
| F-300 | Açık format spesifikasyonu | ADR-003'e göre `docs/spec/volume-format.md` (slotlar + metadata), `preboot-handoff.md`, `ipc.md`. Kod bunlara göre yazılır. | infra |
| F-281 | Birim testleri ve test vektörleri | Test altyapısı: `cargo test` + xUnit; resmi vektörler (IEEE 1619 XTS, RFC 9106 Argon2, XChaCha20 taslak vektörleri) `tests/vectors/` altında. | infra |
| F-288 | SBOM ve bağımlılık denetimi | `cargo-deny` (lisans allowlist, yasaklı crate'ler), `cargo-audit`, CycloneDX SBOM üretimi; CI'da bloklayıcı. | infra |
| F-290 | VM test ortamı | `tests/vm/`: Hyper-V Gen2 VM'yi PowerShell ile oluşturan, KDNET kernel debug'ı açan, test-signing'i kuran betikler; OVMF + QEMU ile bootloader testi. | infra |
| F-127 | Test-signing kurulumu | `tools/sign/`: geliştirici sertifikası oluşturma, `signtool` ile driver imzalama, `bcdedit /set testsigning on` rehberi ve Secure Boot uyarısı. | infra |
| F-013 | Algoritma çevikliği | Format ve kodda `cipher_suite` kimliği; algoritmalar bir kayıt tablosundan seçilir. Faz 0'da arayüz (trait) tanımlanır. | core, cipher |
| F-160 | Sıfır telemetri garantisi | CI'da `cargo-deny` ile `core`, `cipher`, `svc` için ağ crate'leri yasaklanır; README'de taahhüt. Ağ kullanan özellikler ayrı crate'te ve varsayılan kapalı. | infra |

## Faz 1 · Kripto çekirdeği ve format → v0.1-alpha

Amaç: diskteki her baytı üreten ve okuyan kodu bitirmek. Çıktı: CLI ile container oluşturan ve header'ı doğrulayan
sürüm (mount yok).

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-001 | AES-256-XTS veri şifreleme | `toxic-cipher`: RustCrypto `aes` (AES-NI otomatik algılama) + XTS; tweak = mutlak sektör numarası. IEEE 1619 vektörleriyle test. | cipher |
| F-021 | Kuantuma dayanıklı simetrik çekirdek | Tüm simetrik anahtarlar 256-bit, hash'ler 256-bit+; spesifikasyonda Grover analizi belgelenir. Ek kod gerekmez. | core |
| F-002 | XChaCha20-Poly1305 header şifreleme | Slot sarmalama ve metadata bloğu AEAD ile; AAD'de `volume_id` ve slot numarası. | core |
| F-041 | Argon2id parola türetme | RustCrypto `argon2`; region_salt + faktör sırrı `secret` parametresine. RFC 9106 vektörleriyle test. | core |
| F-042 | Maliyet seviyesi (PIM benzeri) | `KdfCost` 1-64 (64 MiB × seviye); sistem volume'unda en fazla 16. Diskte saklanmaz. | core |
| F-043 | Keyfile desteği | İlk 1 MiB'ın BLAKE2b-256 özeti, sıraya bağımsız birleştirme; `DerivationFactor` olarak. | core |
| F-044 | Keyfile klasörü | CLI/servis klasördeki dosyaları ad sırasıyla okuyup F-043'e verir; gizli/sistem dosyaları hariç, en fazla 64 dosya. | cli, svc |
| F-045 | Keyfile üretici | OS CSPRNG'den 64 KiB rastgele dosya; `toxic keyfile new`. | cli |
| F-052 | İpucu saklamama politikası | Formatta ipucu alanı yok; spesifikasyonda gerekçesiyle yazılır. | core |
| F-054 | Veri yeniden şifrelemeden parola değişimi | Yalnızca ilgili slot yeniden sarılır; metadata ve diğer slotlar değişmez. | core |
| F-059 | Çoklu parola slotu | ADR-003 ile formatta 8 slot; CLI'da `toxic slot add/remove`. GUI'deki slot listesi Faz 7'de, F-087 ile birlikte gelir. | core, cli |
| F-141 | Rastgeleden ayırt edilemeyen format | Header bölgesinde magic yok; boş slotlar rastgele. Testte χ² ve entropi kontrolü. | core |
| F-155 | Sabit boyutlu header'lar | 64 KiB sabit bölge; slot ve metadata boyutları sabit. | core |
| F-161 | Anahtarları sıfırlama | Tüm anahtar tipleri `Zeroize + ZeroizeOnDrop`; `Clone` yok; `Debug` gizler. | core, cipher |
| F-163 | Sabit zamanlı karşılaştırmalar | `subtle` crate; AEAD doğrulaması zaten sabit zamanlı; dudect testi Faz 9'da. | core |
| F-221 | Otomatik header yedeği | Container sonunda yedek bölge, farklı nonce'larla ayrıca sarılır. | core |
| F-224 | 48 haneli kurtarma anahtarı | 256-bit rastgele sır → BitLocker benzeri 8×6 hane gösterim (mod 11 kontrol haneli); ayrı bir slota sarılır. | core, cli |
| F-003 | Serpent-256-XTS | `toxic-cipher`'a Serpent (bitsliced, sabit zamanlı) eklenir; NESSIE vektörleri. | cipher |
| F-004 | Twofish-256-XTS | Twofish eklenir; resmi vektörler. Tablo tabanlı olduğundan önbellek yan kanalı spesifikasyonda belirtilir. | cipher |
| F-164 | Bit-sliced AES | AES-NI yoksa `aes` crate'in fixslice yazılım yolu kullanılır; CI'da `RUSTFLAGS` ile AES-NI kapalı test. | cipher |
| F-012 | Algoritma benchmark'ı | `toxic benchmark`: her paket için bellekte MB/s ölçümü; GUI'de Faz 3'te gösterilir. | cli |
| F-282 | Fuzzing | `cargo-fuzz` hedefleri: slot açma, metadata ayrıştırma, keyfile birleştirme. Her PR'da kısa, gecelik uzun koşu. | infra |

## Faz 2 · Driver, servis ve CLI → v0.2-alpha

Amaç: container'ı Windows'ta gerçek bir disk olarak bağlamak.

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-121 | Sanal disk driver'ı | Storport sanal miniport (`StorPortInitialize` + `VIRTUAL_HW_INITIALIZATION_DATA`); her mount bir LUN. Container I/O'su kernel'de `ZwReadFile/ZwWriteFile` ile. | disk |
| F-123 | AES-NI / VAES hızlandırma | `toxic-cipher` staticlib çalışma zamanında CPUID ile yol seçer; VAES yolu `KeSaveExtendedProcessorState` ile korunur. | disk, cipher |
| F-124 | Çok çekirdekli şifreleme | Büyük I/O'lar sektör grupları hâlinde CPU başına iş öğelerine bölünür. | disk |
| F-125 | Asenkron I/O kuyruğu | Storport kuyruk derinliği + tamamlanma rutinleri; senkron bekleme yok. | disk |
| F-126 | Non-paged pool anahtar saklama | Anahtarlar `NonPagedPoolNx`'te; dismount ve unload'da `RtlSecureZeroMemory`. | disk |
| F-136 | IOCTL erişim denetimi | Kontrol cihazı `IoCreateDeviceSecure` + SDDL `D:P(A;;GA;;;SY)`; her IOCTL'de giriş boyutu ve alanları yeniden doğrulanır. | disk |
| F-137 | Unload koruması | Bağlı volume varken `DriverUnload` reddedilir; servis önce tümünü dismount eder. | disk |
| F-130 | Driver Verifier denetimi | VM entegrasyon testleri Driver Verifier açıkken koşar; CI'da `/analyze` (SAL) ve CodeQL. | infra |
| F-081 | Container dosyası oluşturma | Servis: dosyayı `CREATE_NEW` ile oluşturur, slotları yazar, veri alanını şifreli sıfırlarla doldurur (ilerleme bildirimli). | svc |
| F-082 | Sürücü harfiyle mount | Servis IOCTL ile LUN ekler; Windows diski tanır; Mount Manager üzerinden harf atanır. | svc, disk |
| F-083 | Klasöre mount | `SetVolumeMountPointW` ile boş NTFS klasörüne. | svc |
| F-089 | Dosya sistemi seçimi | Oluşturma sonrası `Format-Volume` eşdeğeri (VDS/`fmifs` API) ile NTFS, exFAT, FAT32. | svc |
| F-091 | Salt okunur mount | LUN salt okunur bayrağıyla sunulur; yazma isteklerine `STATUS_MEDIA_WRITE_PROTECTED`. | disk |
| F-097 | Volume bilgi ekranı | Metadata'dan algoritma, boyut, oluşturma tarihi, slot sayısı; Faz 2'de `toxic info`, Faz 3'te GUI. | cli, gui |
| F-261 | toxic CLI | `create`, `mount`, `dismount`, `list`, `info`, `passwd`, `benchmark`, `keyfile`; servise IPC ile. | cli |
| F-262 | JSON çıktı modu | Her komutta `--json`; şema `docs/spec/cli-json.md`'de sabit. | cli |
| F-276 | Kabuk otomatik tamamlama | `clap_complete` ile PowerShell, Bash, Zsh betikleri; kurulumla gelir. | cli |
| F-162 | VirtualLock ile kilitli bellek | Servis hassas tamponları `VirtualLock`'lu sayfalardan ayırır; çalışma kümesi limiti yükseltilir. | svc |
| F-176 | Süreç izolasyonu | GUI orta bütünlükte; servis SYSTEM ama yalnızca gerekli ayrıcalıklarla (`SeChangeNotify`, `SeManageVolume`), diğerleri `AdjustTokenPrivileges` ile kaldırılır. | svc |
| F-178 | Bellek dökümü engeli | Servis `WerAddExcludedApplication` ile hata raporundan çıkarılır; `MiniDumpWriteDump`'a karşı süreç DACL'i sıkılaştırılır. | svc |
| F-080 | Donanım RNG karıştırma | `BCryptGenRandom` + RDRAND (varsa) + TPM `GetRandom` (varsa) çıktıları BLAKE2b ile birleştirilir; tek kaynak arızası güvenliği düşürmez. | svc |
| F-133 | Benchmark aracı | Bağlı volume üzerinde sıralı/rastgele okuma-yazma testi (`toxic benchmark --volume X:`). | cli |

## Faz 3 · Arayüz → v0.3 (MVP)

Amaç: teknik olmayan bir kullanıcının kurup kullanabileceği ilk sürüm.

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-241 | WinUI 3 arayüz | Windows App SDK, MVVM, Mica; ana ekranda bağlı volume'lar ve favoriler. | gui |
| F-242 | Koyu ve açık tema | Sistem temasını izler; marka renkleri `ThemeResource` sözlüğünde. | gui |
| F-243 | Türkçe ve İngilizce | `.resw` kaynakları; CLI mesajları için de aynı anahtar seti. | gui, cli |
| F-252 | Yüksek DPI ve çoklu monitör | Per-monitor DPI v2; vektör ikonlar. | gui |
| F-244 | Container oluşturma sihirbazı | Konum → boyut → algoritma → parola/keyfile → maliyet → biçimlendirme → özet. | gui |
| F-250 | İlerleme ve kalan süre | Servis IPC üzerinden ilerleme akışı yayınlar; GUI hareketli ortalama ile kalan süre hesaplar. | gui, svc |
| F-046 | Parola gücü ölçer | zxcvbn algoritması + Türkçe sözlük; tahmini kırılma süresi Argon2id maliyetine göre gösterilir. | gui |
| F-048 | Diceware parola üretici | EFF ve Türkçe kelime listeleri, CSPRNG ile; kelime sayısı seçilebilir. | gui, cli |
| F-246 | Sistem tepsisi ikonu | Bağlı volume sayısı, hızlı mount/dismount menüsü. | gui |
| F-247 | Sürükle-bırak mount | `.txc` dosyası pencereye bırakılınca parola penceresi açılır. | gui |
| F-248 | Explorer sağ tık menüsü | `IExplorerCommand` + sparse package; "Toxic ile aç". | gui, infra |
| F-249 | Bildirimler | Windows App SDK `AppNotification`: mount, dismount, uzun işlem tamamlandı. | gui |
| F-251 | Erişilebilirlik | `AutomationProperties` tüm kontrollerde, tam klavye gezinimi, Narrator testleri, yüksek kontrast teması. | gui |
| F-253 | Güvenlik durumu paneli | Secure Boot, test modu, TPM, pagefile/hiberfil şifreleme ve BitLocker durumunu servisten okur, renkli durumla gösterir. | gui, svc |
| F-257 | Basit ve uzman mod | Basit modda varsayılanlar sabit (AES, maliyet 8, NTFS); uzman modda tüm seçenekler. | gui |
| F-258 | Bağlam yardımı | Her seçeneğin yanında açıklama `TeachingTip`; metinler kaynak dosyalarında. | gui |
| F-286 | İmzalı kurulum paketi | WiX v5 MSI: driver'lar `pnputil`, servis kaydı, GUI; MSI ve tüm ikililer imzalı. | infra |
| F-271 | Sessiz kurulum | `msiexec /qn` parametreleri (`INSTALLFEATURES`, `NOTRAY`); belgelenir. | infra |

## Faz 4 · Bölüm şifreleme, kurtarma, donanım anahtarları, acil durum → v0.4

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-122 | Volume filter driver | Disk sınıfı alt filtresi; bölüm aralığına düşen I/O şifrelenir; anahtar bölüm başına. | flt |
| F-084 | Bölüm ve disk şifreleme | Boş bölüm/USB için: Layout A, tamamen biçimlendirerek. Dolu bölüm Faz 7 (F-085). | svc, flt |
| F-222 | Header yedeğini dışa aktarma | Header bölgesinin şifreli kopyası dosyaya; içinde sır yoktur, yine parola gerekir. | svc, gui |
| F-223 | Header geri yükleme | Yedekten bölgeyi geri yazmadan önce yedeğin verilen parolayla açıldığı doğrulanır. | svc, gui |
| F-049 | İki faktörlü kilit açma | Volume politikası "parola + donanım faktörü"; iki türetme faktörü Argon2id sırrında birleşir, biri eksikse türetilen anahtar farklı olur. | core, svc |
| F-053 | Yanlış deneme gecikmesi | Servis volume_id bazında üstel gecikme (1, 2, 4… en fazla 60 sn); çevrimdışı saldırıyı değil arayüzden denemeyi yavaşlatır. | svc |
| F-055 | Oturum boyunca anahtar önbelleği | Header anahtarı değil, girilen faktör sırları kilitli bellekte süreli tutulur; ekran kilidi ve uykuda silinir. | svc |
| F-061 | YubiKey challenge-response | HMAC-SHA1 slot 2; challenge = region_salt; yanıt türetme faktörü olur. USB HID üzerinden `toxic-factors`. | factors |
| F-062 | FIDO2 hmac-secret | Discoverable credential (`rpId = toxic.local`) + `hmac-secret` uzantısı, salt = region_salt. Windows `webauthn.dll` API v3+ ile; desteklemeyen sürümde doğrudan CTAP2 HID. | factors |
| F-070 | USB'de keyfile | Kayıtlı USB (seri no) takılınca keyfile oradan okunur ve volume açılır; parola istenip istenmeyeceği politikada. | svc |
| F-071 | USB çıkınca otomatik kilit | `RegisterDeviceNotification`; kayıtlı aygıt kalkınca ilgili volume'lar zorla dismount. | svc |
| F-169 | Ekran kilitlenince dismount | `WTSRegisterSessionNotification` → `WTS_SESSION_LOCK`'ta seçili volume'lar dismount. | svc |
| F-170 | Uyku öncesi dismount | `PBT_APMSUSPEND` / Modern Standby bildiriminde dismount ve faktör önbelleği silme. | svc |
| F-181 | Panik kısayolu | Global kısayol (varsayılan Ctrl+Alt+Shift+F12) → tüm volume'ları zorla dismount, önbellekleri sil, GUI'yi kapat. | gui, svc |
| F-182 | Header imhası | İki aşamalı onay + volume adını yazdırma; birincil bölge 3 kez CSPRNG ile ezilir, `FlushFileBuffers`. | svc |
| F-196 | Yedek header'ı da imha etme | F-182'nin seçeneği; yedek bölge ve dışa aktarılmış yedekler hakkında uyarı. | svc |
| F-183 | Kriptografik silme | Tüm disk/bölüm için header + yedek imhası; veri alanı anahtarsız kalır, saniyeler sürer. | svc |
| F-184 | Güvenli dosya silme | Dosya içeriği üzerine yazılır, ad rastgeleleştirilir, sonra silinir; SSD'de garantinin olmadığı açıkça yazılır ve kriptografik silme önerilir. | svc, gui |
| F-189 | Hatalı deneme kaydı | İsteğe bağlı, hash zincirli yerel kayıt (zaman, volume_id kısaltması, faktör türü); parola içermez. | svc |
| F-142 | Gizli volume | Dış volume'un veri alanının sonunda ikinci volume; kendi header bölgesi (Slot bölgesi B) ve kendi region_salt'ı. Açarken her iki bölge de denenir (süre farkı sızmasın). Sihirbaz güvenli kullanım kurallarını adım adım anlatır. | core, svc, gui |
| F-143 | Gizli volume koruması | Dış volume mount edilirken gizli volume'un parolası da verilirse driver gizli alana düşen yazmaları reddeder ve volume'u salt okunur'a çeker; kullanıcıya bildirilir. | disk, svc |
| F-144 | Baskı (duress) parolası | Gizli volume'lu yapıda dış volume parolası baskı parolası olarak kullanılır; arayüzde bu ilişki ve sınırları açıkça anlatılır. Ayrı bir "zararsız container" profili de seçilebilir. | svc, gui |
| F-299 | Uyumluluk test matrisi | VM matrisi: Windows 10 22H2, 11 23H2/24H2; Hyper-V ve VMware firmware'leri; BitLocker açık/kapalı. | infra |

## Faz 5 · Uygulama Kilidi (WinLock entegrasyonu) → v0.5

Tasarım: mimari ADR-013. WinLock'tan taşınan fikirler Rust'a yeniden yazılır; kernel tarafı yenidir.

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| A-01 | Kernel süreç başlatma kapısı | `PsSetCreateProcessNotifyRoutineEx2`; korunan imaj izinsizse `STATUS_ACCESS_DENIED` + servise olay. | guard |
| A-02 | Toxic kimlik doğrulama penceresi | Servis kullanıcı oturumunda (`WTSQueryUserToken` + `CreateProcessAsUser`) yardımcı pencereyi açar; parola, Hello, FIDO2, TOTP. Pencere ekran kaydından hariç (`WDA_EXCLUDEFROMCAPTURE`). | svc, gui |
| A-03 | Güçlü uygulama kimliği | Eşleşme: Authenticode yayıncısı + SHA-256 + yol; dosya kopyalayıp adını değiştirerek atlatma engellenir. Güncellemede yayıncı aynıysa hash otomatik yenilenir. | svc, guard |
| A-04 | Yeniden başlatma | İzin verilince süreç orijinal komut satırı, çalışma dizini ve kullanıcı token'ıyla yeniden başlatılır; driver'a süreli izin yazılır. | svc |
| A-05 | Oturum izni (grace) | Uygulama başına "N dakika boyunca tekrar sorma"; ekran kilidinde sıfırlanır. | svc |
| A-06 | Alt süreç kalıtımı | İzinli süreç bir Job Object'e alınır; alt süreçler izni devralır (Steam → oyun). | svc |
| A-07 | Uygulama + veri kilidi | Uygulama bir Toxic volume'una bağlanır: kilit açılınca volume mount edilir, uygulama kapanınca dismount edilir. | svc |
| A-08 | Öz-koruma | `ObRegisterCallbacks` ile servis sürecine yönetici olmayanların `PROCESS_TERMINATE` erişimi kaldırılır; `CmRegisterCallbackEx` ile App Lock yapılandırması korunur. | guard |
| A-09 | Paketli uygulama desteği | Store/MSIX uygulamaları Package Family Name ile tanımlanır. | svc |
| A-10 | Zamanlama ve politika | Uygulama başına haftalık saat ızgarası ve faktör gereksinimi (WinLock'taki gibi). | svc, gui |
| A-11 | Uyumluluk modu (driver'sız) | Driver yüklenemezse WinLock'un IFEO + ETW yöntemi; arayüzde daha zayıf olduğu açıkça yazılır. | svc |
| A-12 | WinLock'tan içe aktarma | WinLock uygulama listesini ve ayarlarını okuyup Toxic kurallarına dönüştürme (parola taşınmaz, yeniden belirlenir). | svc, gui |

## Faz 6 · Sistem şifreleme (ToxicBoot) → v1.0

Önkoşul: VM'de en az 500 tam açılış/şifreleme/çözme döngüsü hatasız tamamlanmadan gerçek donanımda çalıştırılmaz.

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-101 | ToxicBoot UEFI bootloader | Rust `uefi` crate, `x86_64-unknown-uefi`; `toxic-core` ile header açma; BlockIo sarmalama; ADR-007 el sıkışması; `bootmgfw.efi` zincirleme. | boot |
| F-102 | Sistem bölümünü yerinde şifreleme | Layout B: dosya sistemi 128 KiB küçültülür, header bölgesi sona yazılır; `toxicflt` sektörleri sırayla şifreler. | flt, svc |
| F-103 | Duraklat ve devam et | Her 64 MiB'da metadata'daki `encrypted_size` güncellenir (iki aşamalı yazım: önce veri, `FlushFileBuffers`, sonra metadata). | flt, svc |
| F-104 | Kurtarma USB'si oluşturma | FAT32 USB'ye ToxicBoot, header bölgesi kopyası ve kurtarma menüsü (header geri yükle, tamamen çöz). Şifreleme bu adım olmadan başlamaz. | svc, boot |
| F-105 | Türkçe açılış ekranı | Metinler bootloader içinde gömülü tablo; dil kurulumda seçilir. ABD klavyesi uyarısı. | boot |
| F-107 | Toxic logolu açılış ekranı | `assets/brand/boot/*.bmp` GOP üzerinden çizilir; GOP yoksa metin modu. | boot |
| F-108 | Görünmez parola girişi | Tuş basımında hiçbir geri bildirim yok (isteğe bağlı nokta gösterimi kapalı varsayılan). | boot |
| F-109 | Deneme limiti | N hatalı denemede `ResetSystem`; sayaç bellekte, kalıcı değil. | boot |
| F-114 | Windows güncellemesi sonrası onarım | Servis her açılışta ESP'deki boot sırasını ve `bootmgfw.efi` yolunu denetler; Windows değiştirdiyse ToxicBoot'u yeniden ilk sıraya alır. | svc |
| F-119 | Açılış sonrası bellek temizliği | `ExitBootServices` öncesi parola ve ara anahtarlar sıfırlanır; el sıkışma sayfası driver tarafından sıfırlanır. | boot, flt |
| F-120 | Sistem şifrelemesini kaldırma | Ters yönde sektör sektör çözme, aynı ilerleme mekanizmasıyla; bitince ToxicBoot kaldırılıp Windows Boot Manager geri yüklenir. | flt, svc |
| F-191 | Boot bütünlük kontrolü | Servis ToxicBoot ve ESP dosyalarının SHA-256'sını kurulumda kaydeder, her açılışta karşılaştırır ve fark varsa uyarır. | svc |
| F-245 | Sistem şifreleme sihirbazı | Ön kontroller (UEFI, GPT, BitLocker kapalı, pil/AC, yedek onayı), kurtarma USB'si zorunlu adım, VM'de prova önerisi. | gui |

## Faz 7 · Algoritmalar ve uyumluluk → v1.1

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-005 | İkili kaskad (AES → Serpent) | Bağımsız anahtarlarla sıralı XTS; cipher_suite kimliği ile. | cipher |
| F-006 | Üçlü kaskad | Aynı yapı, üç katman; master key 192 B. | cipher |
| F-007 | Camellia-256-XTS | RFC 3713 vektörleri; AES-NI benzeri hızlandırma yoksa yazılım yolu. | cipher |
| F-008 | Kuznyechik | GOST R 34.12-2015 vektörleri; yalnızca uyumluluk için, önerilmeyen olarak işaretli. | cipher |
| F-009 | Adiantum | ChaCha12 + AES-256 + NH/Poly1305; AES-NI olmayan cihazlarda varsayılan önerisi. | cipher |
| F-014 | Arka planda master key rotasyonu | Yeni master key ile Layout B mekanizmasının aynısı: iki anahtar aynı anda yüklü, sınır metadata'da. | flt, disk, svc |
| F-015 | Yerinde algoritma değiştirme | F-014 ile aynı motor; eski ve yeni cipher_suite birlikte. | flt, disk, svc |
| F-017 | VeraCrypt volume açma | VeraCrypt belgelerine göre header okuyucu (PBKDF2-SHA512/Whirlpool/SHA256/Streebog, PIM); salt okunur başlar. TrueCrypt lisanslı kod kopyalanmaz. | core |
| F-018 | TrueCrypt eski volume desteği | F-017 okuyucusunun TrueCrypt modu; yalnızca salt okunur. | core |
| F-020 | FIPS 140-3 modu | "Yalnızca onaylı algoritmalar" modu (AES, SHA-2, PBKDF2 yerine Argon2 olmadığı için ayrı KDF profili). Resmi sertifika bu kapsamda değildir. | core, svc |
| F-085 | Dolu bölümü yerinde şifreleme | Faz 6'daki yerinde şifreleme motoru sistem dışı bölümlere uygulanır. | flt, svc |
| F-087 | Container büyütme | Dosya uzatılır, yeni alan şifreli sıfırla doldurulur, yedek bölge taşınır, metadata güncellenir, dosya sistemi genişletilir. | svc, disk |
| F-090 | ReFS desteği | ReFS biçimlendirmenin desteklendiği sürümlerde (Dev Drive dahil) seçenek. | svc |
| F-098 | Volume etiketi ve ikonu | Metadata'da etiket; Explorer ikonu için `DefaultIcon` registry anahtarı mount süresince. | svc |
| F-099 | Ağ paylaşımındaki container | Kernel UNC yolunu açar; ağ kesintisinde I/O hataları güvenli biçimde yüzeye çıkar, otomatik dismount. | disk |
| F-100 | SSD TRIM desteği | `UNMAP` komutları container dosyasında `FSCTL_SET_ZERO_DATA`'ya çevrilir; boş alanı sızdırdığı uyarısıyla isteğe bağlı. | disk |
| F-230 | Kısmi kurtarma aracı | Header açılınca veri alanı sektör sektör okunur, okunamayanlar atlanarak yeni container'a kopyalanır. | svc, cli |
| F-240 | Reed-Solomon hata düzeltme | Header bölgesine RS parite; tek-bit çürümelerinde AEAD'den önce düzeltme. Formatta ayrılmış alan Faz 1'de bırakılır. | core |

## Faz 8 · TPM, donanım ve gelişmiş açılış → v1.2

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-064 | TPM 2.0 ölçümlü açılış | ToxicBoot kendini PCR 4'e ölçtürür; hızlı açma blob'u PCR 4+7 politikasıyla mühürlenir. Değişiklikte parola istenir. | boot, factors |
| F-065 | TPM + PIN | Mühürleme politikasına `PolicyAuthValue` (PIN) eklenir; TPM'in sözlük saldırısı koruması deneme sayısını sınırlar. | boot, factors |
| F-063 | Açılış ekranında FIDO2 | ToxicBoot'ta USB HID + CTAP2 istemcisi (hmac-secret); Windows'taki ile aynı credential. | boot |
| F-066 | Windows Hello ile hızlı açma | Hello KSP'deki anahtarla sabit bir challenge'ın deterministik RSA imzası → hızlı açma blob'unun anahtarı. Sistem diskinde kullanılamaz. | factors, gui |
| F-074 | Opal SED yönetimi | `IOCTL_STORAGE_*` güvenlik protokolü komutlarıyla TCG Opal: kilitleme aralıkları, PSID ile sıfırlama. | svc |
| F-075 | Nitrokey / OnlyKey desteği | FIDO2 yolu zaten çalışır; HMAC challenge-response için cihaza özel HID komutları. | factors |
| F-079 | Kill switch USB | Kayıtlı USB'nin takılması panik eylemini tetikler (F-181 ile aynı motor). | svc |
| F-194 | Kablo kill-switch | Kayıtlı USB'nin çıkarılması panik eylemini tetikler (manyetik kopma kablosuyla). | svc |
| F-106 | Türkçe Q klavye desteği | UEFI'den gelen ABD tuş karakterleri konuma göre TR-Q eşlemesine çevrilir; parola UTF-8 NFC olarak türetilir. | boot |
| F-110 | Sahte hata ekranı | Parola ekranı yerine firmware'e benzer "boot device not found" metni; gizli tuş dizisiyle parola alanı. | boot |
| F-111 | Çoklu disk tek parola | Aynı parolayla açılan tüm diskler için anahtarlar el sıkışma sayfasında liste olarak. | boot, flt |
| F-112 | Dual-boot desteği | ToxicBoot menüsünde diğer EFI yükleyicileri (Linux shim/grub) zincirleme. | boot |
| F-113 | Kendi Secure Boot anahtarın | Rehber + araç: kullanıcı anahtarı oluşturma, `db`'ye Microsoft anahtarlarının yanına ekleme, ToxicBoot'u imzalama. | infra, boot |
| F-116 | Şifreli hibernate | `toxicflt` dump filtresi olarak kaydolur; hiberfil yazımları şifrelenir, açılışta ToxicBoot çözer. | flt, boot |
| F-117 | Şifreli crash dump | Aynı dump filtresi crash dump yazımlarına uygulanır. | flt |
| F-190 | Evil-maid tespiti | TPM PCR değerleri ve ESP hash'leri karşılaştırılır; değişiklik varsa Windows açıldığında güçlü uyarı. | svc |
| F-128 | Microsoft attestation imzası | EV sertifika + Partner Center; driver paketleri attestation'a gönderilir; test modu gereksinimi kalkar. | infra |
| F-129 | Yeniden başlatmadan driver güncelleme | Bağlı volume yoksa servis driver'ı durdurup yenisini yükler; varsa bir sonraki açılışa ertelenir. | svc, infra |

## Faz 9 · Sertleştirme ve platform → v1.3

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-165 | Cold boot koruması | Container'lar için kilitte dismount; sistem diski için uyku yerine hibernate zorlama seçeneği ve anahtarın tek kopyada tutulması. | svc, flt |
| F-168 | DMA saldırı koruması | Kernel DMA Protection durumunu denetler; kilitliyken yeni Thunderbolt aygıtlarını reddeden ilke önerir ve uygular. | svc |
| F-173 | Güvenli masaüstünde parola | Parola penceresi `CreateDesktop` ile ayrı masaüstünde (UAC benzeri); diğer süreçler pencereye ulaşamaz. | gui, svc |
| F-174 | Ekran klavyesi | Güvenli masaüstünde, tuş konumları her açılışta karıştırılabilir. | gui |
| F-175 | Spectre/Meltdown kontrolü | `NtQuerySystemInformation` spekülatif kontrol bilgisiyle yamalar denetlenir, güvenlik panelinde gösterilir. | svc |
| F-177 | Debugger tespiti | Kritik işlemlerde debugger varsa uyarı ve işlemi reddetme; açık kaynak olduğundan yalnızca caydırıcı olduğu belgelenir. | svc |
| F-179 | Guard page'li ayırıcı | Hassas tamponlar için iki yanında `PAGE_NOACCESS` sayfalı özel ayırıcı. | svc |
| F-185 | Boş alan temizleme | Şifresiz bir volume'da boş alanı geçici dosyayla doldurup silme; SSD uyarısı. | svc, gui |
| F-186 | N hatalı denemede imha | Varsayılan kapalı, çift onaylı; yedek header yoksa etkinleştirilemez; sayaç servis tarafında. | svc |
| F-134 | Düşük güç modu | Pilde iş parçacığı sayısı ve önbellek davranışı azaltılır. | disk, svc |
| F-135 | ARM64 Windows desteği | Tüm bileşenler ARM64 için derlenir; `toxic-cipher` ARMv8 kripto uzantılarını kullanır. | tümü |
| F-152 | Taşınabilir mod | USB'den çalışan GUI + driver'ı geçici yükleyip çıkarken kaldıran mod (yönetici gerekir). | gui, svc |
| F-156 | Nötr görünüm modu | Uygulama adı, ikon ve tepsi görünümü nötr seçeneklere çevrilir. | gui |
| F-157 | Tuzak volume'lar | Belirtilen boyutta tamamen rastgele `.txc` dosyaları üretir. | cli, gui |
| F-047 | Sızdırılmış parola kontrolü | HIBP k-anonimlik API'si (SHA-1 ilk 5 hane); varsayılan kapalı, ağ kullandığı açıkça belirtilir. | gui |
| F-297 | Yerel çökme raporu | Yalnızca yerel, anahtarsız mini rapor; kullanıcı isterse kendisi paylaşır. | svc, gui |
| F-298 | Performans regresyon testleri | CI'da her sürümde sabit donanım profiliyle benchmark; %5 düşüş bloklayıcı. | infra |

## Faz 10 · Kuantum sonrası → v1.4

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-022 | ML-KEM-1024 anahtar sarma | PQ slot türü: `kem_ct` alanı; slot anahtarı = HKDF(ML-KEM paylaşılan sır). | core |
| F-023 | Hibrit X25519 + ML-KEM | Slot anahtarı = HKDF(ML-KEM sırrı ‖ X25519 sırrı ‖ transkript); biri kırılsa da diğeri korur. | core |
| F-026 | Kuantum sonrası kurtarma anahtarı | Yönetici/kişisel PQ anahtar çifti; özel anahtar parola ile korunur ya da Shamir ile bölünür. | core, svc |
| F-027 | PQ güvenli container paylaşımı | Alıcının PQ açık anahtarına yeni slot eklenir; alıcı kendi özel anahtarıyla açar. | core, gui |
| F-030 | Kuantum tehdit raporu | Volume'ların slot türlerini ve algoritmalarını tarayıp risk tablosu üretir. | svc, gui |
| F-032 | Harvest-now-decrypt-later koruması | Ağa çıkan tüm anahtar alışverişleri yalnızca hibrit PQ kanalla (F-033) yapılır; politika olarak zorunlu. | svc |
| F-034 | Kriptografik envanter (CBOM) | Kullanılan algoritmaların CycloneDX CBOM formatında listesi, her sürümde üretilir. | infra |
| F-040 | NIST PQC test vektörleri | FIPS 203/204/205 resmi vektörleri test setine eklenir. | infra |
| F-024 | ML-DSA imzalı güncellemeler | Sürüm manifesti Ed25519 + ML-DSA-65 ile imzalanır. | infra |
| F-287 | İmzalı otomatik güncelleme | Güncelleyici iki imzayı ve sabitlenmiş açık anahtarları doğrular; varsayılan "kontrol et, sor". | svc, gui |

## Faz 11 · Vault ve bulut → v2.0

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-201 | Vault modu | Dosya bazlı format: dosya başına anahtar, 64 KiB bloklar halinde AEAD; vault anahtarı Toxic slotlarıyla sarılı. | core, svc |
| F-202 | Minifilter ile şeffaf vault | `toxicvault.sys` minifilter; vault klasörü uygulamalara açık metin görünür, diskte şifreli durur (oturum açıkken). | vault |
| F-203 | Dosya adı şifreleme | AES-SIV ile deterministik ad şifreleme, base32 kodlama. | core |
| F-206 | Değişen blok senkronu | Container değişen blokları kaydeder; bulut istemcisinin parça senkronuna uygun düzen (sabit 4 MiB parçalar). | disk, svc |
| F-033 | PQ TLS ile bulut senkronu | Bulut bağlantıları hibrit X25519+ML-KEM TLS 1.3 (rustls) üzerinden. | svc |

## Faz 12 · Otomasyon ve arayüz geliştirmeleri → v2.1

| ID | Özellik | Nasıl yapılacak | Bileşen |
|---|---|---|---|
| F-263 | PowerShell modülü | `Toxic` modülü, CLI'ın JSON çıktısını saran cmdlet'ler (`Mount-ToxicVolume` vb.). | cli |
| F-265 | Olay tetikleyicileri | Servis kuralları: USB takıldı, ağa bağlandı, oturum açıldı → mount/dismount/panik. | svc |
| F-273 | SIEM'e denetim kaydı | Denetim kaydı ETW sağlayıcısı + isteğe bağlı Syslog (TLS) aktarımı. | svc |
| F-255 | Komut paleti (Ctrl+K) | Tüm eylemler aranabilir listede. | gui |
| F-256 | Animasyonlu kilit ikonu | Zehir damlası kilitleme/açılma animasyonu (Lottie veya Composition API). | gui |
| F-260 | İlk açılış güvenlik turu | Beş adımlık rehber: parola, yedek, kurtarma, panik tuşu, güvenlik paneli. | gui |

## Ar-Ge hattı · Sürekli, paralel

Her madde önce bir **fizibilite raporu** (`docs/research/F-xxx.md`) ile başlar: tehdit modeline katkısı, uygulanabilirlik,
bakım maliyeti. Olumlu sonuçlanan madde bir faza alınır; olumsuz sonuçlanan madde gerekçesiyle kapatılır.

| ID | Özellik | Araştırma yaklaşımı |
|---|---|---|
| F-010 | Sektör bazlı kimlik doğrulama | Etiketleri saklamak için ayrı metadata alanı (dm-integrity yaklaşımı); performans ve atomiklik ölçümü. |
| F-011 | Merkle bütünlük ağacı | Salt okunur volume'lar için dm-verity benzeri ağaç; yazılabilir volume'larda maliyet analizi. |
| F-016 | Wide-block şifreleme (HCTR2) | HCTR2'nin `toxic-cipher`'a eklenmesi; XTS'ye göre hız kıyası. |
| F-019 | BitLocker volume okuma | Belgelenmemiş formatın açık kaynak analizlerine göre bağımsız implementasyon; salt okunur. |
| F-025 | SLH-DSA imzalı bootloader | ToxicBoot'un kendi imza doğrulaması; açılış süresine etkisi. |
| F-028 | Kuantum RNG | USB QRNG cihazından okuma ve F-080 karıştırıcısına ekleme. |
| F-029 | QKD deneyi | Yalnızca literatür ve uygulanabilirlik raporu; donanım olmadan ürünleşmez. |
| F-031 | Argon2id + PQ KEM sır karıştırma | PQ slotunun türetme faktörü olarak parola ile birleşimi; inkâr edilebilirlik etkisi. |
| F-036 | Threefish-512 | Uzun vadeli arşiv profili; 512-bit anahtarın gerçek kazanımı. |
| F-038 | OPAQUE uzaktan kilit açma | Ev sunucusuyla OPAQUE (RFC 9807) tabanlı açma. |
| F-039 | PQ donanım anahtarı hazırlığı | `DerivationFactor` arayüzünün PQ FIDO uzantılarına uyumu. |
| F-067 | Pre-boot parmak izi | Belgelenmiş protokollü okuyucu var mı araştırması. |
| F-068 | NFC kart ile kilit açma | PC/SC üzerinden NFC kart (ör. YubiKey NFC, NTAG424 imzası) türetme faktörü olarak. |
| F-072 | HSM desteği | PKCS#11 üzerinden sarma anahtarı. |
| F-073 | SGX / SEV | Masaüstü uygunluğu (karar 4); olumsuz çıkarsa F-140'a yönlendirilir. |
| F-088 | Container küçültme | Dosya sistemi küçültme + veri taşıma + header yeniden konumlandırma güvenliği. |
| F-118 | Gizli işletim sistemi | F-142/F-143 Faz 4'te geldikten sonra; gizli volume'dan ikinci Windows'u açan ToxicBoot akışı ve sızıntı analizi. |
| F-139 | Rust driver modülleri | `windows-drivers-rs` olgunluğu; `toxic-cipher` dışındaki modüller için. |
| F-140 | VBS enclave anahtar koruması | Windows 11 VBS enclave API'si ile XTS işlemlerinin enclave içinde yapılması; imza gereksinimleri. |
| F-145 | Çok katmanlı gizli volume | F-142 üzerine; üçüncü bir header bölgesinin rastgelelik ve alan analizi. |
| F-146 | Container'ı medya dosyası gibi gösterme | Geçerli bir ISO/MP4 başlığı taşıyan polyglot container. |
| F-147 | Steganografik container | Gerçek medya içine gömme; kapasite ve tespit edilebilirlik ölçümü. |
| F-166 | Anahtarı CPU register'ında tutma | Windows'ta uygulanabilirlik (karar 4). |
| F-167 | Hassas verileri RAM'de şifreleme | Servis içi hassas durumun oturum anahtarıyla şifrelenmesi; maliyet/kazanç. |
| F-188 | Uzaktan kilit komutu | Telefondan imzalı komut; ağ dinleme gerektirmeyen tasarım (çekme modeli). |
| F-193 | Sahte çökme | F-144 üzerine; baskı parolasında bootloader'ın bozuk disk davranışı taklidi. |
| F-195 | Acil durum kişisi | Çevrimdışı tasarım mümkün mü; ağ gerektiriyorsa ayrı modül. |
| F-204 | Klasör yapısı gizleme | Vault'ta dosya sayısı/boyutu sızıntısını paketlemeyle önleme. |
| F-209 | Şifreli paylaşım bağlantısı | Tek dosya için PQ hibrit paylaşım paketi. |
| F-211 | Mobil görüntüleyici | `toxic-core`'un Android/iOS'a derlenmesi; vault okuma. |
| F-234 | Header geçmişi | Eski parolanın açık kalma riskine karşı kazanım analizi. |
| F-237 | Şifreli disk imajı | Sektör seviyesinde tam disk yedeği formatı. |
| F-239 | Çoklu disk yedekliliği | Container'ın iki diske aynalanması. |
| F-254 | Windows widget'ı | Windows App SDK widget sağlayıcısı. |
| F-270 | Intune / MDM | ADMX ve OMA-URI yapılandırma profilleri. |
| F-272 | Active Directory anahtar emaneti | Kurtarma anahtarının AD nesnesine yazılması (BitLocker'a benzer). |
| F-274 | WSL2'ye şifreli disk | Toxic diski `wsl --mount --bare` ile WSL'e geçirme. |
| F-275 | VS Code eklentisi | Proje gizlerini vault'ta tutan eklenti. |
| F-277 | Ansible / Terraform modülü | Sunucu otomasyonu. |
| F-278 | İmzalı eklenti sistemi | Eklenti API'si ve imza modeli; saldırı yüzeyi analizi. |
| F-279 | Yerel webhook'lar | Olayların yerel HTTP uç noktalarına iletilmesi. |
| F-283 | Formel doğrulama | Header ve metadata ayrıştırıcısının Kani ile kanıtlanması. |
| F-291 | Linux sürümü | Header'ı açan CLI + dm-crypt `aes-xts-plain64` tablosu (mutlak sektör tweak'i dm-crypt ile uyumlu). |
| F-292 | macOS sürümü | FSKit veya macFUSE ile kullanıcı modu yaklaşımı. |

---

## Sayım

| Faz | Özellik sayısı |
|---|---:|
| Faz 0 | 9 |
| Faz 1 | 22 |
| Faz 2 | 22 |
| Faz 3 | 18 |
| Faz 4 | 23 |
| Faz 5 | 12 (App Lock, yeni) |
| Faz 6 | 13 |
| Faz 7 | 18 |
| Faz 8 | 18 |
| Faz 9 | 17 |
| Faz 10 | 10 |
| Faz 11 | 5 |
| Faz 12 | 6 |
| Ar-Ge | 44 |
| **Toplam seçili** | **225** (+12 App Lock) |
