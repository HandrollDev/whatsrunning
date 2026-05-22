"""Build whatsrunning.ico (multi-resolution) and whatsrunning-logo.png.

These are kept in sync with the in-app shield drawn by `make_logo()` in
whatsrunning.py: same proportions, same bezier-curved shield bottom, same
checkmark coordinates, same round line caps. Run after any change to the
in-app logo's geometry so the .exe icon and the rendered PNG stay aligned.

Run with:  python build_icon.py
"""

from PIL import Image, ImageDraw


ACCENT = (47, 129, 247, 255)   # matches the in-app ACCENT colour
WHITE = (255, 255, 255, 255)


def _bezier_point(t: float, p0, p1, p2, p3):
    """One point on a cubic bezier curve at parameter t ∈ [0, 1]."""
    mt = 1.0 - t
    return (
        mt * mt * mt * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t * t * t * p3[0],
        mt * mt * mt * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t * t * t * p3[1],
    )


def _sample_bezier(p0, p1, p2, p3, steps=32):
    """Return `steps+1` points along the cubic bezier curve p0→p1→p2→p3."""
    return [_bezier_point(i / steps, p0, p1, p2, p3) for i in range(steps + 1)]


def draw_shield(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s = float(size)

    # Shield outline — matches the QPainterPath in whatsrunning.make_logo().
    # Top-center -> top-right -> mid-right, then a smooth bezier curve along
    # the bottom to mid-left, then back up to top-left.
    pts: list[tuple[float, float]] = []
    pts.append((0.50 * s, 0.06 * s))      # top centre
    pts.append((0.92 * s, 0.22 * s))      # top right
    pts.append((0.92 * s, 0.55 * s))      # mid right
    # Right-side bezier curve to bottom point
    pts.extend(_sample_bezier(
        (0.92 * s, 0.55 * s),
        (0.92 * s, 0.82 * s),
        (0.72 * s, 0.94 * s),
        (0.50 * s, 0.96 * s),
        steps=32,
    ))
    # Left-side bezier curve back up to mid-left
    pts.extend(_sample_bezier(
        (0.50 * s, 0.96 * s),
        (0.28 * s, 0.94 * s),
        (0.08 * s, 0.82 * s),
        (0.08 * s, 0.55 * s),
        steps=32,
    ))
    pts.append((0.08 * s, 0.22 * s))      # top left
    # polygon closes back to start automatically
    draw.polygon(pts, fill=ACCENT)

    # Checkmark — three points, matching make_logo() exactly. PIL's `joint='curve'`
    # rounds the corner where the two strokes meet; the `width` ensures the
    # stroke matches the in-app pen width (10% of size).
    line_w = max(2, int(round(s * 0.10)))
    draw.line(
        [(0.30 * s, 0.52 * s), (0.45 * s, 0.67 * s), (0.72 * s, 0.38 * s)],
        fill=WHITE,
        width=line_w,
        joint="curve",
    )
    # Pillow's line() draws with flat caps by default. Cover both endpoints
    # with circles to mimic the in-app round-cap pen, so the checkmark looks
    # the same as the on-screen logo.
    r = line_w / 2
    for cx, cy in ((0.30 * s, 0.52 * s), (0.72 * s, 0.38 * s)):
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=WHITE)

    return img


def _render_supersampled(target_size: int, supersample: int = 4) -> Image.Image:
    """Render the shield at `target_size`, but draw it at `supersample`× that
    resolution first and downsample with LANCZOS — gives clean anti-aliased
    edges that Pillow's `draw.line()` and `draw.polygon()` don't produce
    natively. Without this, lines look stair-stepped at any size."""
    over = target_size * supersample
    big = draw_shield(over)
    return big.resize((target_size, target_size), Image.LANCZOS)


def main() -> None:
    sizes = [16, 32, 48, 64, 128, 256]
    # 256-pixel base — used as the largest entry in the multi-resolution
    # .ico, and PIL downsamples it for the smaller sizes too.
    base = _render_supersampled(256, supersample=4)
    base.save(
        "whatsrunning.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
    )
    print(f"Wrote whatsrunning.ico with sizes {sizes}")

    # PNG at 1024×1024 for the README header, Open Graph / Twitter cards,
    # and any other web context where the icon gets shown larger than 96px.
    # Rendering at 1024 (with 4× supersample under the hood = 4096) means
    # social platforms that downsample to ~600px get a crisp result.
    png = _render_supersampled(1024, supersample=4)
    png.save("whatsrunning-logo.png", format="PNG")
    print("Wrote whatsrunning-logo.png (1024x1024, anti-aliased)")


if __name__ == "__main__":
    main()
