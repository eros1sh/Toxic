# Toxic marka varlıkları

Logo: **Zehir damlası** — anahtar deliği oyulmuş zehir damlası.

## Renkler

| Token | Hex | Kullanım |
|---|---|---|
| `toxic-lime` | `#A3E635` | Birincil marka rengi, logo, vurgu |
| `toxic-ink` | `#0B0F0A` | Koyu zemin, ikon kutusu, boot ekranı |
| `toxic-paper` | `#F4F7EE` | Açık zemin ve koyu zemin üzerindeki metin |
| `toxic-danger` | `#EF4444` | Hata, yanlış parola, kritik uyarılar |

## Dosyalar

| Klasör | İçerik |
|---|---|
| `svg/toxic-icon.svg` | Koyu kutulu uygulama ikonu (kaynak) |
| `svg/toxic-mark.svg` | Şeffaf zeminli damla (yeşil) |
| `svg/toxic-mark-mono.svg` | Tek renk, `currentColor` ile boyanır |
| `png/` | İkon 16–1024 px, damla 128–512 px |
| `ico/toxic.ico` | Windows ikonu (16–256 px, 10 boyut) |
| `boot/` | UEFI boot ekranı için 24-bit BMP (64/128/256 px) |

32 px ve altındaki ikonlarda anahtar deliği okunabilirlik için büyütülmüştür.

Yeniden üretmek için:

```bash
py -3 -I tools/brand/render_brand.py assets/brand
```
