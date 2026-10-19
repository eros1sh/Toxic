# Toxic Volume Header Formatı — Sürüm 1

Durum: **Taslak v1 — ADR-003 onaylanınca anahtar slotları ve metadata bloğuyla yeniden yazılacak** (bkz. `docs/architecture.md`) · Referans implementasyon: `crates/toxic-core`

Bu belge, Toxic'in container dosyaları, şifreli bölümler ve sistem şifrelemesi için kullandığı disk üzerindeki
formatı tanımlar. UEFI bootloader, kernel driver, servis ve CLI bu belgeye **birebir** uymak zorundadır.
Belge ile referans implementasyon çelişirse, hata kabul edilir ve ikisi birlikte düzeltilir.

Anahtar sözcükler: **ZORUNLU**, **YASAK**, **ÖNERİLİR** (RFC 2119 anlamında).

---

## 1. Tasarım hedefleri

1. **Rastgelelikten ayırt edilemezlik.** Diskteki hiçbir bayt açık metin değildir: magic, sürüm, KDF
   parametresi veya bayrak yoktur. Doğru parola olmadan bir Toxic volume'u rastgele veriden ayırt edilemez.
   Bu, gizli volume'ların inkâr edilebilirliğinin temelidir.
2. **Kimlik doğrulamalı header.** Header AEAD ile şifrelenir. Yanlış parola, bozuk header ve
   değiştirilmiş header aynı sonucu verir: `InvalidCredentials`. Ayrım dışarı sızdırılmaz.
3. **Parola değişimi veri yeniden şifrelemesi gerektirmez.** Veri, header içindeki rastgele master key
   ile şifrelenir; parola yalnızca header'ı sarar.
4. **Her katmanda aynı kod.** Format `no_std` ortamda (UEFI) ayrıştırılabilir olacak şekilde sabit
   boyutlu ve little-endian'dır.

## 2. Kriptografik yapı taşları

| Amaç | Algoritma | Parametre |
|---|---|---|
| Paroladan header anahtarı | Argon2id, sürüm 0x13 | Bkz. §4 |
| Header şifreleme | XChaCha20-Poly1305 | 256-bit anahtar, 192-bit nonce, 128-bit tag |
| Veri şifreleme | AES-256-XTS (IEEE 1619) | 512-bit master key, data unit = sektör |
| Keyfile özeti | BLAKE2b-256 | Bkz. §5 |
| Rastgelelik | İşletim sistemi CSPRNG'si | Windows: `BCryptGenRandom`; UEFI: `EFI_RNG_PROTOCOL` |

Tüm çok baytlı tamsayılar **little-endian**'dır.

## 3. Header slot'u

Bir **slot** tam olarak **65 536 bayt** (64 KiB) uzunluğundadır:

| Offset | Boyut | Alan | Açıklama |
|---:|---:|---|---|
| 0 | 32 | `salt` | Argon2id salt'ı, CSPRNG'den |
| 32 | 24 | `nonce` | XChaCha20-Poly1305 nonce'u, CSPRNG'den |
| 56 | 512 | `ciphertext` | Şifreli header gövdesi (§6) |
| 568 | 16 | `tag` | Poly1305 kimlik doğrulama etiketi |
| 584 | 64 952 | `padding` | CSPRNG'den rastgele bayt |

- AEAD ilişkili verisi (AAD): ASCII `toxic-header-v1` (15 bayt).
- Her yazımda `salt` ve `nonce` **yeniden üretilmek ZORUNDADIR**. Aynı (anahtar, nonce) çifti tekrar
  kullanılmamalıdır.
- `padding` her yazımda yeniden rastgele doldurulur. Okuyucular `padding`'i yok sayar.

### 3.1 Kullanılmayan slot

Gizli volume bulunmayan bir volume'da gizli slot **tamamen CSPRNG çıktısıyla** doldurulur. Böylece gizli
volume olan ve olmayan bir container dışarıdan aynı görünür.

## 4. Anahtar türetme (KDF)

```
header_key = Argon2id(
    password   = P            (§4.2),
    salt       = slot.salt    (32 bayt),
    secret     = K            (§5; keyfile yoksa boş),
    associated = "toxic-header-v1",
    m_cost     = 65 536 × cost  KiB,
    t_cost     = 3,
    p_cost     = 4,
    out_len    = 32
)
```

### 4.1 Maliyet seviyesi (`cost`)

KDF parametreleri diskte saklanmaz (§1.1). Bunun yerine kullanıcı bir **maliyet seviyesi** seçer ve kilit
açarken aynı seviyeyi girer (VeraCrypt'teki PIM'e karşılık gelir).

| `cost` | Bellek | Not |
|---:|---:|---|
| 1 | 64 MiB | En düşük; yalnızca zayıf donanım için, arayüz uyarı göstermeli |
| **8** | **512 MiB** | **Varsayılan.** Kullanıcı seviye girmezse bu kullanılır |
| 16 | 1 GiB | Sistem (boot) volume'ları için üst sınır |
| 64 | 4 GiB | Mutlak üst sınır |

- Geçerli aralık: `1 ≤ cost ≤ 64`. Dışındaki değerler **reddedilir**.
- `SYSTEM` bayrağı taşıyan volume'larda `cost ≤ 16` **ZORUNLUDUR** (UEFI ortamındaki bellek sınırı).
- Kullanıcıya varsayılan dışı bir seviye girdiğinde bunu hatırlaması gerektiği açıkça söylenmelidir;
  seviye unutulursa volume açılamaz.

### 4.2 Parola kodlaması

1. Parola UTF-8 olarak alınır ve **Unicode NFC** biçimine normalize edilir.
2. Kodlanmış uzunluk **0–256 bayt** olmalıdır. Boş parolaya yalnızca en az bir keyfile varsa izin verilir.
3. `SYSTEM` bayrağı taşıyan volume'larda parola yalnızca **yazdırılabilir ASCII** (`0x20–0x7E`) içerebilir.
   Gerekçe: UEFI öncesi ortamda klavye düzeni ABD düzenidir; `ğ`, `ş`, `ı` gibi karakterler güvenilir
   biçimde girilemez. Oluşturma aracı bu kuralı **oluşturma anında** uygulamalıdır.

## 5. Keyfile'lar

```
d_i = BLAKE2b-256( "toxic-keyfile-v1" ‖ keyfile_i[0 .. min(len, 1 MiB)] )
K   = BLAKE2b-256( "toxic-keyfiles-v1" ‖ u32le(n) ‖ sort(d_1 … d_n) )
```

- Her keyfile'ın **ilk 1 MiB'ı** kullanılır (büyük medya dosyaları keyfile olarak kullanılabilsin diye).
- Özetler bayt sırasına göre sıralanır; böylece keyfile'ların veriliş sırası sonucu etkilemez.
- En fazla **64** keyfile. Keyfile yoksa `K` boş dizidir (Argon2 `secret` parametresi kullanılmaz).
- Boş (0 bayt) keyfile **reddedilir**.

## 6. Header gövdesi (512 bayt, şifreli)

| Offset | Boyut | Tip | Alan | Kural |
|---:|---:|---|---|---|
| 0 | 8 | ASCII | `magic` | `TOXICHDR` |
| 8 | 2 | u16 | `format_version` | `1` |
| 10 | 2 | u16 | `min_reader_version` | `1`; okuyucunun sürümünden büyükse volume açılmaz |
| 12 | 4 | u32 | `flags` | §6.1 |
| 16 | 2 | u16 | `cipher` | `1` = AES-256-XTS |
| 18 | 2 | u16 | `kdf_cost` | Bu header'ı sararken kullanılan `cost` (§4.1) |
| 20 | 4 | u32 | `sector_size` | `512` veya `4096` |
| 24 | 16 | bayt | `volume_id` | Rastgele, volume'u tanımlar |
| 40 | 8 | u64 | `created_unix` | Oluşturma zamanı (UTC saniye) |
| 48 | 8 | u64 | `data_offset` | Şifreli veri alanının volume başından offset'i (bayt) |
| 56 | 8 | u64 | `data_size` | Şifreli veri alanının boyutu (bayt) |
| 64 | 8 | u64 | `encrypted_offset` | Şu ana kadar şifrelenmiş bölgenin başlangıcı (mutlak) |
| 72 | 8 | u64 | `encrypted_size` | Şu ana kadar şifrelenmiş bölgenin boyutu |
| 80 | 64 | bayt | `master_key` | `K1 ‖ K2`: K1 = veri anahtarı, K2 = tweak anahtarı |
| 144 | 368 | bayt | `reserved` | v1'de **tamamen sıfır** |

### 6.1 Bayraklar

| Bit | Ad | Anlam |
|---:|---|---|
| 0 | `SYSTEM` | Volume işletim sisteminin boot bölümüdür; bootloader tarafından açılır |
| 1 | `HIDDEN` | Bu header bir gizli volume'a aittir |
| 2 | `IN_PLACE` | Yerinde şifreleme düzeni (Layout B, §7.2) |
| 3 | `ENCRYPTING` | Yerinde şifreleme sürüyor; yalnızca `encrypted_*` bölgesi şifrelidir |

Tanımsız bitlerden biri 1 ise header **reddedilir**.

### 6.2 Doğrulama kuralları

Açılan bir header aşağıdakilerin hepsini sağlamalıdır; aksi halde `InvalidCredentials` değil,
`UnsupportedHeader` / `CorruptHeader` döner (AEAD zaten doğrulandığı için bu ayrım güvenlidir):

1. `magic == "TOXICHDR"`, `min_reader_version ≤ 1`, `cipher == 1`.
2. `sector_size ∈ {512, 4096}`; `data_offset`, `data_size`, `encrypted_offset`, `encrypted_size` sektör hizalı.
3. `data_size > 0` ve `data_offset + data_size` taşma yapmaz.
4. `ENCRYPTING` yoksa: `encrypted_offset == data_offset` ve `encrypted_size == data_size`.
   `ENCRYPTING` varsa: şifreli bölge veri alanının içinde kalır.
5. `K1 ≠ K2` (IEEE 1619 gereği; oluşturucu eşitse yeniden üretir).
6. `1 ≤ kdf_cost ≤ 64`; `SYSTEM` varsa `kdf_cost ≤ 16`.
7. `HIDDEN` ile `SYSTEM` veya `IN_PLACE` aynı anda kullanılamaz (v1'de gizli işletim sistemi yoktur).
8. `reserved` tamamen sıfır.

## 7. Volume düzenleri

`S` = volume'un toplam boyutu (container dosyası ya da bölüm), `SLOT = 65 536`.

### 7.1 Layout A — container ve ayrılmış bölüm

```
0            64K          128K                                  S-128K       S-64K        S
├─ Slot A ───┼─ Slot B ───┼──────────── veri alanı ──────────────┼─ Yedek A ───┼─ Yedek B ───┤
   normal      gizli/rnd                                            normal       gizli/rnd
```

- Normal volume: `data_offset = 131 072`, `data_size = S − 262 144`.
- `S` 4096'nın katı ve en az **1 MiB + 256 KiB** olmalıdır.
- **Yedek header'lar farklı `salt` ve `nonce` ile ayrıca sarılır**; birincil ile yedeğin aynı ciphertext'i
  taşıması YASAKTIR (yoksa aynı içerik taşıdıkları anlaşılır).
- **Gizli volume**, dış volume'un veri alanının sonunda yaşar: `data_offset = S − 131 072 − hidden_size`,
  `data_size = hidden_size`. Dış volume header'ı gizli volume hakkında **hiçbir bilgi taşımaz**.
- Yeni oluşturulan veri alanı, volume anahtarıyla şifrelenmiş sıfırlarla **tamamen doldurulmalıdır**.
  "Hızlı biçimlendirme" ile boş alanın rastgele olmaması inkâr edilebilirliği bozar.

### 7.2 Layout B — yerinde şifreleme (sistem ve dolu bölümler)

```
0                                                     S-128K       S-64K        S
├────────────────────── veri alanı ─────────────────────┼─ Slot A ───┼─ Slot B ───┤
```

- `data_offset = 0`, `data_size = S − 131 072`. Şifrelemeden önce dosya sistemi en az 128 KiB küçültülür.
- Birincil ve yedek aynı arıza bölgesinde olmasın diye **yedek, kurtarma medyasında** tutulur:
  kurtarma dosyası `[Slot A ‖ Slot B]` (131 072 bayt) içerir. Kurtarma medyası olmadan sistem
  şifrelemesi **başlatılamaz**.
- Şifreleme sürerken `ENCRYPTING` bayrağı açıktır ve her ilerleme adımında header yeniden yazılır
  (yeni salt + nonce). Kesinti sonrası işlem `encrypted_*` alanlarından devam eder.

## 8. Veri şifreleme

- Algoritma: AES-256-XTS, `K1` veri anahtarı, `K2` tweak anahtarı.
- Data unit boyutu: `sector_size`.
- Tweak: **volume başından mutlak** data unit numarası, 128-bit little-endian:
  `unit = absolute_offset / sector_size`.
  Mutlak numara kullanılması, Layout B'de veri taşımadan yerinde şifrelemeyi mümkün kılar.
- Veri alanı dışındaki bölgeler (header slot'ları) XTS ile şifrelenmez.

## 9. İşlemler

### 9.1 Açma

1. Kullanıcıdan parola, isteğe bağlı keyfile'lar ve `cost` alınır (girilmezse 8).
2. Slot A ile denenir; başarısızsa **Slot B** ile denenir (gizli volume). Her deneme ayrı bir Argon2id
   hesaplamasıdır; iki slotun da her zaman denenmesi ÖNERİLİR (süre farkı gizli volume'un varlığını
   ele vermesin).
3. İkisi de başarısızsa `InvalidCredentials` döner. **Yedek header'lar otomatik denenmez**; kullanıcı
   açıkça "yedek header'ı kullan" seçeneğini seçer.
4. Başarılı açılışta §6.2 doğrulamaları uygulanır.

### 9.2 Parola / keyfile / cost değişimi

- Yalnızca açılan slot yeniden yazılır (yeni salt, nonce, padding; aynı master key).
- **Diğer slota dokunmak YASAKTIR**: gizli volume'un varlığı bilinemeyeceği için Slot B'ye rastgele veri
  yazmak gizli volume'u yok edebilir.
- Önce birincil, sonra yedek yazılır; her yazımdan sonra disk önbelleği boşaltılır (`FlushFileBuffers`).

### 9.3 Bellek hijyeni

`master_key`, `header_key`, parola ve keyfile özetleri kullanımdan sonra sıfırlanmalı (`zeroize`),
mümkün olan yerde swap'a düşmeyecek bellekte tutulmalıdır (`VirtualLock` / kernel non-paged pool).

## 10. Sürümleme

- Yeni alanlar `reserved` alanından alınır ve `format_version` artırılır.
- Eski okuyucuların güvenle açamayacağı bir değişiklikte `min_reader_version` da artırılır.
- Algoritma değişikliği (ör. yeni şifre) yeni bir `cipher` kimliği ile yapılır; `1` asla yeniden tanımlanmaz.

## 11. Test vektörleri

Referans test vektörleri `crates/toxic-core/tests/` altındadır ve `cargo test -p toxic-core` ile doğrulanır.
Bootloader ve driver implementasyonları aynı vektörleri geçmek **ZORUNDADIR**.
