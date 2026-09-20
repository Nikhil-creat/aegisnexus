"""Turn raw bytes into images and entropy maps.

Malware-as-image (Nataraj et al., 2011): every byte becomes a grayscale pixel,
so structure such as code, text, padding and packed/encrypted regions shows up
as visual texture that a CNN can learn. Files are only ever *read as bytes* -
they are never executed, parsed or opened by an interpreter.
"""
from __future__ import annotations

import math

import numpy as np

IMG_SIZE = 64
GRID = 8

_WIDTHS = [
    (10 * 1024, 32),
    (30 * 1024, 64),
    (60 * 1024, 128),
    (100 * 1024, 256),
    (200 * 1024, 384),
    (500 * 1024, 512),
    (1024 * 1024, 768),
]


def _width_for(n: int) -> int:
    for limit, width in _WIDTHS:
        if n < limit:
            return width
    return 1024


def bytes_to_image(data: bytes, size: int = IMG_SIZE) -> np.ndarray:
    """Return a float32 array of shape (size, size) with values in [0, 1]."""
    if not data:
        return np.zeros((size, size), dtype=np.float32)
    buf = np.frombuffer(data, dtype=np.uint8)
    width = _width_for(buf.size)
    height = math.ceil(buf.size / width)
    padded = np.zeros(height * width, dtype=np.uint8)
    padded[: buf.size] = buf
    img = padded.reshape(height, width)
    rows = np.linspace(0, height - 1, size).astype(int)
    cols = np.linspace(0, width - 1, size).astype(int)
    return img[np.ix_(rows, cols)].astype(np.float32) / 255.0


def shannon_entropy(buf: np.ndarray) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if buf.size == 0:
        return 0.0
    counts = np.bincount(buf, minlength=256).astype(np.float64)
    p = counts[counts > 0] / buf.size
    return float(-(p * np.log2(p)).sum())


def block_entropy_grid(buf: np.ndarray, grid: int = GRID) -> np.ndarray:
    """Normalised entropy (0..1) of grid*grid consecutive chunks of the file."""
    chunks = np.array_split(buf, grid * grid)
    out = np.zeros(grid * grid, dtype=np.float32)
    for i, chunk in enumerate(chunks):
        if chunk.size < 2:
            continue
        h_max = math.log2(min(256, chunk.size))
        out[i] = min(1.0, shannon_entropy(chunk) / h_max)
    return out.reshape(grid, grid)


def pixel_entropy_map(img: np.ndarray, grid: int = GRID, bins: int = 16) -> np.ndarray:
    """Spatially aligned (grid x grid) map of local pixel-value entropy in [0, 1].

    Used as the explanation heat-map by the heuristic engine: random-looking (packed or
    encrypted) regions glow, structured code/text/padding stays dark. With the CNN
    engine, Grad-CAM plays this role instead."""
    n = img.shape[0]
    step = n // grid
    q = np.minimum((img * bins).astype(int), bins - 1)
    out = np.zeros((grid, grid), dtype=np.float32)
    for y in range(grid):
        for x in range(grid):
            block = q[y * step:(y + 1) * step, x * step:(x + 1) * step].ravel()
            counts = np.bincount(block, minlength=bins)
            p = counts[counts > 0] / block.size
            out[y, x] = float(-(p * np.log2(p)).sum() / math.log2(min(bins, block.size)))
    return out
