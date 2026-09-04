#!/usr/bin/env python3
"""
OG Image Generator for GitHub Pages landing pages.
Generates a 1200x630 PNG following the Flow Series dark gradient theme.

Usage:
    python3 og-image-template.py "SeoFlow" "🌊" "AI SEO pipeline in your repo" og-image.png
    python3 og-image-template.py "SECflow" "🔐" "Zero-cost security scanning for AI-driven repos" og-image.png
    python3 og-image-template.py "BacklinkFlow" "🔗" "Zero-cost backlink & directory submission" og-image.png

Requirements: Pillow (pip install pillow)
"""

import sys
import os
from PIL import Image, ImageDraw, ImageFont


def find_font(size):
    """Find a usable system font at the given size."""
    font_paths = [
        "/System/Library/Fonts/SFNS.ttf",           # macOS
        "/System/Library/Fonts/SFCompact.ttf",      # macOS
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",  # Linux
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",              # Windows
        r"C:\Windows\Fonts\arialbd.ttf",
    ]
    for fp in font_paths:
        if os.path.exists(fp):
            try:
                return ImageFont.truetype(fp, size)
            except Exception:
                pass
    return ImageFont.load_default()


def create_og_image(title, icon, subtitle, output_path, subtitle_lines=1):
    """
    Create a 1200x630 OG image with the Flow Series dark gradient theme.

    Args:
        title: The repo name (e.g. "SeoFlow")
        icon: Emoji icon (e.g. "🌊")
        subtitle: Short description (can contain \\n for multi-line)
        output_path: Where to save the PNG
        subtitle_lines: Number of lines in subtitle (for vertical centering)
    """
    W, H = 1200, 630
    img = Image.new("RGB", (W, H), "#0f172a")
    draw = ImageDraw.Draw(img)

    # Gradient background: blend from #0f172a to #1e293b
    for y in range(H):
        t = y / H
        r = int(15 + t * (30 - 15))
        g = int(23 + t * (41 - 23))
        b = int(42 + t * (75 - 42))
        draw.line([(0, y), (W, y)], fill=(r, g, b))

    font_title = find_font(64)
    font_sub = find_font(32)
    font_small = find_font(24)

    # Title with accent color
    draw.text((W // 2, 200), title, fill="#38bdf8", font=font_title, anchor="mt")

    # Subtitle
    lines = subtitle.split("\n")
    y_pos = 280 + (30 if len(lines) == 2 else 0)
    for line in lines:
        draw.text((W // 2, y_pos), line, fill="#cbd5e1", font=font_sub, anchor="mt")
        y_pos += 42

    # Footer
    draw.text(
        (W // 2, H - 100),
        f"npx {title.lower()} scan  •  MIT licensed  •  Free forever",
        fill="#94a3b8",
        font=font_small,
        anchor="mb",
    )

    img.save(output_path, "PNG")
    print(f"✓ Created {output_path} ({os.path.getsize(output_path)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 og-image-template.py <title> <icon> <subtitle> <output>")
        print("Example: python3 og-image-template.py \"SeoFlow\" \"🌊\" \"AI SEO pipeline in your repo\" og-image.png")
        sys.exit(1)

    title = sys.argv[1]
    icon = sys.argv[2]
    subtitle = sys.argv[3]
    output = sys.argv[4]
    create_og_image(title, icon, subtitle, output)
