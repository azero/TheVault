#!/usr/bin/env python3
"""WCAG AA contrast check for the colour pairs used in server/internal/web/static/app.css.

Run: python3 tests/contrast.py   (exit 1 on failure). Add a pair here for any new colour combination.
"""
import sys


def lum(h):
    h = h.lstrip("#")
    r, g, b = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# (name, foreground, background, minimum ratio)
LIGHT = [
    ("text on bg", "#0b1220", "#f2f4f8", 4.5), ("text on surface", "#0b1220", "#ffffff", 4.5), ("text on surface-3", "#0b1220", "#eceff5", 4.5),
    ("muted on surface", "#46536a", "#ffffff", 4.5), ("muted on bg", "#46536a", "#f2f4f8", 4.5), ("muted on surface-3", "#46536a", "#eceff5", 4.5),
    ("accent text on surface", "#1d4ed8", "#ffffff", 4.5), ("accent text on accent-soft", "#1d4ed8", "#e8efff", 4.5),
    ("primary button", "#ffffff", "#1d4ed8", 4.5), ("primary button hover", "#ffffff", "#1e40af", 4.5),
    ("danger", "#b42318", "#fef3f2", 4.5), ("success", "#067647", "#ecfdf3", 4.5), ("warn", "#93370d", "#fffaeb", 4.5), ("info", "#175cd3", "#eff8ff", 4.5),
    ("gold text on surface", "#8a5a12", "#ffffff", 4.5), ("danger button", "#ffffff", "#b42318", 4.5),
    ("input border", "#7a869a", "#ffffff", 3.0), ("focus ring on surface", "#2563eb", "#ffffff", 3.0),
    ("toast", "#f2f4f8", "#0b1220", 4.5),
    ("avatar 0", "#3730a3", "#e0e7ff", 4.5), ("avatar 1", "#9d174d", "#fce7f3", 4.5), ("avatar 2", "#166534", "#dcfce7", 4.5), ("avatar 3", "#92400e", "#fef3c7", 4.5),
    ("avatar 4", "#075985", "#e0f2fe", 4.5), ("avatar 5", "#6b21a8", "#f3e8ff", 4.5), ("avatar 6", "#9a3412", "#ffedd5", 4.5), ("avatar 7", "#334155", "#e2e8f0", 4.5),
]
DARK = [
    ("text on bg", "#e7ecf5", "#080c14", 4.5), ("text on surface", "#e7ecf5", "#0e1522", 4.5), ("text on surface-3", "#e7ecf5", "#18233a", 4.5),
    ("muted on surface", "#9fb0c9", "#0e1522", 4.5), ("muted on bg", "#9fb0c9", "#080c14", 4.5), ("muted on surface-3", "#9fb0c9", "#18233a", 4.5),
    ("accent text on surface", "#8bb8ff", "#0e1522", 4.5), ("accent text on accent-soft", "#8bb8ff", "#10223f", 4.5),
    ("primary button", "#04101f", "#5b9bff", 4.5), ("primary button hover", "#04101f", "#7db0ff", 4.5),
    ("danger", "#ff9a92", "#2a1517", 4.5), ("success", "#5ddc9a", "#0f2a1c", 4.5), ("warn", "#f5b04a", "#2b2010", 4.5), ("info", "#7db4ff", "#0f2036", 4.5),
    ("gold text on surface", "#f2c15a", "#0e1522", 4.5), ("danger button", "#1a0606", "#ff9a92", 4.5),
    ("input border", "#6b7a96", "#0e1522", 3.0), ("focus ring on surface", "#8bb8ff", "#0e1522", 3.0),
    ("toast", "#080c14", "#e7ecf5", 4.5),
    ("avatar 0", "#c7d2fe", "#1e2350", 4.5), ("avatar 1", "#fbcfe8", "#4a1530", 4.5), ("avatar 2", "#bbf7d0", "#123524", 4.5), ("avatar 3", "#fde68a", "#3d2a0a", 4.5),
    ("avatar 4", "#bae6fd", "#0c2a40", 4.5), ("avatar 5", "#e9d5ff", "#34154d", 4.5), ("avatar 6", "#fed7aa", "#3f1d0b", 4.5), ("avatar 7", "#cbd5e1", "#252b38", 4.5),
]

bad = 0
for mode, pairs in (("light", LIGHT), ("dark", DARK)):
    for name, fg, bg, need in pairs:
        r = ratio(fg, bg)
        if r < need:
            bad += 1
            print(f"FAIL {mode:5} {name}: {fg} on {bg} = {r:.2f} (need {need})")
print("all colour pairs pass WCAG AA" if not bad else f"{bad} failing pair(s)")
sys.exit(1 if bad else 0)
