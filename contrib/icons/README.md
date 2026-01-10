# DRFW Icons

## For Packagers

Install only the PNG files, not the SVG. The SVG uses fonts and features that render inconsistently across different icon renderers.

```bash
for size in 16 24 32 48 64 128 256 512; do
    install -Dm644 "drfw-${size}.png" "$pkgdir/usr/share/icons/hicolor/${size}x${size}/apps/drfw.png"
done
```

## Regenerating PNGs

The SVG is kept as the source file for future edits. To regenerate the PNGs:

**Requirements:**
- Inkscape 1.4+
- M+1Code Nerd Font (`ttf-mplus-nerd` on Arch)

**Command:**
```bash
for size in 16 24 32 48 64 128 256 512; do
    inkscape contrib/icons/drfw.svg --export-filename="contrib/icons/drfw-${size}.png" --export-width=$size --export-height=$size
done
```

## Why PNGs Instead of SVG?

The SVG relies on:
- `M+1Code Nerd Font` for text rendering
- SVG filter primitives for drop shadows
- Clip paths for rounded corners

Some icon renderers (e.g., certain desktop panels/launchers) don't fully support these features, causing text to bleed outside boundaries or shadows to disappear. Pre-rendered PNGs ensure consistent appearance everywhere.
