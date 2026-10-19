"""Toxic marka varlıklarını SVG geometrisiyle birebir aynı şekilde raster'a çevirir."""
from __future__ import annotations

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

LIME = (0xA3, 0xE6, 0x35)
INK = (0x0B, 0x0F, 0x0A)

Point = tuple[float, float]


def cubic(p0: Point, p1: Point, p2: Point, p3: Point, steps: int = 64) -> list[Point]:
    pts: list[Point] = []
    for i in range(1, steps + 1):
        t = i / steps
        u = 1 - t
        x = u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def drop_outline() -> list[Point]:
    # SVG: M128 40 C116 62 74 112 74 150 A54 54 0 0 0 182 150 C182 112 140 62 128 40 Z
    pts: list[Point] = [(128, 40)]
    pts += cubic((128, 40), (116, 62), (74, 112), (74, 150))
    for i in range(1, 129):
        t = math.pi - math.pi * i / 128  # pi -> 0, alt yarım daire
        pts.append((128 + 54 * math.cos(t), 150 + 54 * math.sin(t)))
    pts += cubic((182, 150), (182, 112), (140, 62), (128, 40))
    return pts


def keyhole_parts() -> tuple[tuple[Point, float], list[Point]]:
    circle = ((128.0, 142.0), 14.0)
    trapezoid = [(120.0, 153.5), (136.0, 153.5), (141.0, 182.0), (115.0, 182.0)]
    return circle, trapezoid


def transform(pts: list[Point], scale: float, origin: Point, k: float, offset: Point) -> list[Point]:
    return [((x - origin[0]) * scale * k + offset[0], (y - origin[1]) * scale * k + offset[1]) for x, y in pts]


def render_mask(size: int, ss: int, view: tuple[float, float, float, float], small: bool) -> tuple[Image.Image, Image.Image]:
    """Damla maskesi ve anahtar deliği maskesini (L modunda) döndürür."""
    vx, vy, vw, vh = view
    big = size * ss
    k = big / max(vw, vh)
    off_x = (big - vw * k) / 2
    off_y = (big - vh * k) / 2

    def to_px(pts: list[Point]) -> list[Point]:
        return [((x - vx) * k + off_x, (y - vy) * k + off_y) for x, y in pts]

    drop = drop_outline()
    (cc, cr), trap = keyhole_parts()
    if small:
        # Küçük boyutlarda anahtar deliği kaybolmasın diye delik büyütülür.
        kc = (128.0, 155.0)
        f = 1.25
        trap = [(kc[0] + (x - kc[0]) * f, kc[1] + (y - kc[1]) * f) for x, y in trap]
        cc = (kc[0] + (cc[0] - kc[0]) * f, kc[1] + (cc[1] - kc[1]) * f)
        cr *= f

    drop_mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(drop_mask).polygon(to_px(drop), fill=255)

    hole_mask = Image.new("L", (big, big), 0)
    hd = ImageDraw.Draw(hole_mask)
    hd.polygon(to_px(trap), fill=255)
    (ccx, ccy), = to_px([cc])
    r = cr * k
    hd.ellipse((ccx - r, ccy - r, ccx + r, ccy + r), fill=255)
    return drop_mask, hole_mask


def icon(size: int, small: bool) -> Image.Image:
    ss = 8 if size <= 256 else 4
    big = size * ss
    # Küçük boyutlarda damla kutuyu daha çok doldursun.
    view = (40.0, 32.0, 176.0, 184.0) if small else (0.0, 0.0, 256.0, 256.0)
    drop_mask, hole_mask = render_mask(size, ss, view, small)

    tile_mask = Image.new("L", (big, big), 0)
    radius = int(big * 52 / 256)
    ImageDraw.Draw(tile_mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=radius, fill=255)

    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    img.paste(Image.new("RGBA", (big, big), INK + (255,)), (0, 0), tile_mask)
    lime_mask = Image.composite(Image.new("L", (big, big), 0), drop_mask, hole_mask)
    img.paste(Image.new("RGBA", (big, big), LIME + (255,)), (0, 0), lime_mask)
    return img.resize((size, size), Image.LANCZOS)


def mark(size: int) -> Image.Image:
    ss = 4
    big = size * ss
    drop_mask, hole_mask = render_mask(size, ss, (64.0, 32.0, 128.0, 184.0), small=False)
    alpha = Image.composite(Image.new("L", (big, big), 0), drop_mask, hole_mask)
    img = Image.new("RGBA", (big, big), LIME + (0,))
    img.putalpha(alpha)
    return img.resize((size, size), Image.LANCZOS)


def boot_bmp(size: int) -> Image.Image:
    """UEFI GOP için tam dolu arka planlı 24-bit BMP (şeffaflık yok)."""
    ss = 8
    big = size * ss
    drop_mask, hole_mask = render_mask(size, ss, (32.0, 16.0, 192.0, 216.0), small=size < 96)
    img = Image.new("RGB", (big, big), INK)
    lime_mask = Image.composite(Image.new("L", (big, big), 0), drop_mask, hole_mask)
    img.paste(Image.new("RGB", (big, big), LIME), (0, 0), lime_mask)
    return img.resize((size, size), Image.LANCZOS)


def main(out_root: Path) -> int:
    png_dir = out_root / "png"
    ico_dir = out_root / "ico"
    boot_dir = out_root / "boot"
    for d in (png_dir, ico_dir, boot_dir):
        d.mkdir(parents=True, exist_ok=True)

    icon_sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024]
    icons: dict[int, Image.Image] = {}
    for s in icon_sizes:
        img = icon(s, small=s <= 32)
        icons[s] = img
        img.save(png_dir / f"toxic-icon-{s}.png", optimize=True)

    for s in (128, 256, 512):
        mark(s).save(png_dir / f"toxic-mark-{s}.png", optimize=True)

    ico_sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
    base = icons[256]
    base.save(
        ico_dir / "toxic.ico",
        format="ICO",
        sizes=[(s, s) for s in ico_sizes],
        append_images=[icons[s] for s in ico_sizes if s != 256],
    )

    for s in (64, 128, 256):
        boot_bmp(s).save(boot_dir / f"toxic-boot-{s}.bmp", format="BMP")

    print("ok")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("kullanım: render_brand.py <assets/brand klasörü>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
