#!/usr/bin/env python3
"""Regenerate the web, extension and README logo files from the original (docs/brand/thevault-logo.webp).

  python3 -I docs/brand/make-assets.py        (needs Pillow)

The original is the source of truth; never edit the generated files by hand.
"""
from pathlib import Path
from PIL import Image

root = Path(__file__).resolve().parents[2]
src = Path(__file__).with_name("thevault-logo.webp")
web = root / "server/internal/web/static/brand"
ext = root / "extension/icons"
web.mkdir(parents=True, exist_ok=True)
ext.mkdir(parents=True, exist_ok=True)

im = Image.open(src).convert("RGBA")


def save(name: str, width: int, **kw) -> None:
    h = round(im.height * width / im.width)
    im.resize((width, h), Image.LANCZOS).save(web / name, **kw)


save("thevault-logo.webp", 760, quality=90, method=6)      # sign-in card
save("thevault-logo-nav.webp", 240, quality=90, method=6)  # top bar
im.resize((1000, round(im.height * 1000 / im.width)), Image.LANCZOS).save(
    src.with_name("thevault-logo.png"), optimize=True)     # README only (not embedded in the binary)

# Square emblem: the vault wheel with the blue core (the wordmark is unreadable at 16 px).
EMBLEM = (665, 132, 1005, 472)
emb = im.crop(EMBLEM)
emb.resize((96, 96), Image.LANCZOS).save(web / "mark.png", optimize=True)
emb.resize((64, 64), Image.LANCZOS).save(web / "favicon.png", optimize=True)
bg = Image.new("RGBA", emb.size, (11, 17, 28, 255))  # iOS wants an opaque icon
bg.alpha_composite(emb)
bg.convert("RGB").resize((180, 180), Image.LANCZOS).save(web / "apple-touch-icon.png", optimize=True)
for s in (16, 32, 48, 128):
    emb.resize((s, s), Image.LANCZOS).save(ext / f"icon-{s}.png", optimize=True)

for f in sorted(list(web.iterdir()) + list(ext.iterdir()) + [src.with_name("thevault-logo.png")]):
    print(f"{f.name:26} {f.stat().st_size / 1024:6.1f} KB")
