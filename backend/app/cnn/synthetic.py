"""Synthetic, *harmless* training data.

No real malware is bundled or generated. These generators create byte streams
whose statistical texture imitates the classes below, so the whole pipeline can
be trained, tested and demoed offline. For production, retrain on a real corpus
(Malimg, BODMAS, CIC-IDS2017 ...) - see README, section "Bring your own data".
"""
from __future__ import annotations

import numpy as np

from .bytemap import bytes_to_image

FILE_CLASSES = ["benign", "packed_or_encrypted", "trojan_dropper", "ransomware_like"]
FLOW_CLASSES = ["benign", "syn_flood", "port_scan", "brute_force"]

FLOW_LEN = 16          # packets per flow window
FLOW_CHANNELS = 5      # size, direction, inter-arrival, tcp-flag, dst-port
FLAG_SYN, FLAG_ACK, FLAG_PSH, FLAG_RST = 1, 3, 4, 5

_NOTE = b"SIMULATED NOTE - synthetic training sample, contains no payload. "


# ----------------------------------------------------------------- files ----
def _header(rng: np.random.Generator) -> bytes:
    stub = bytearray(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
    stub += bytes(rng.integers(0, 8, 48, dtype=np.uint8))
    stub += b"This program cannot be run in DOS mode.\r\n$" + bytes(40)
    stub += b"PE\x00\x00L\x01" + bytes(rng.integers(0, 32, 120, dtype=np.uint8))
    return bytes(stub)


def _code(rng: np.random.Generator, n: int) -> bytes:
    p = rng.uniform(0.05, 0.11)
    vals = np.clip(rng.geometric(p, n) - 1, 0, 255).astype(np.uint8)
    if n > 64:
        motif = vals[:16].copy()
        for _ in range(max(1, n // 900)):
            pos = int(rng.integers(0, n - 16))
            vals[pos:pos + 16] = motif
    return vals.tobytes()


def _text(rng: np.random.Generator, n: int) -> bytes:
    alphabet = np.frombuffer(b"etaoinshrdlu cmfwyp.,\n_/\\:0123456789", dtype=np.uint8)
    w = np.linspace(1.0, 0.1, alphabet.size)
    return rng.choice(alphabet, size=n, p=w / w.sum()).tobytes()


def _random(rng: np.random.Generator, n: int) -> bytes:
    return rng.integers(0, 256, n, dtype=np.uint8).tobytes()


def _b64(rng: np.random.Generator, n: int) -> bytes:
    alphabet = np.frombuffer(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", dtype=np.uint8
    )
    return rng.choice(alphabet, size=n).tobytes()


def make_file(kind: str, rng: np.random.Generator) -> bytes:
    if kind not in FILE_CLASSES:
        raise ValueError(f"unknown file kind: {kind}")
    total = int(rng.integers(30_000, 260_000))

    def f(x: float) -> int:
        return max(16, int(total * x))

    if kind == "benign":
        segs = [_header(rng), _code(rng, f(.55)), _text(rng, f(.20)), bytes(f(.10)), _code(rng, f(.15))]
    elif kind == "packed_or_encrypted":
        segs = [_header(rng), _code(rng, f(.02)), _random(rng, f(.98))]
    elif kind == "trojan_dropper":
        segs = [_header(rng), _code(rng, f(.30)), _random(rng, f(rng.uniform(.30, .42))),
                _text(rng, f(.15)), bytes(f(.10)), _code(rng, f(.10))]
    else:  # ransomware_like
        note = (_NOTE * (f(.05) // len(_NOTE) + 1))[: f(.05)]
        segs = [_header(rng), _code(rng, f(.20)), _random(rng, f(rng.uniform(.52, .62))),
                _b64(rng, f(.12)), note, _code(rng, f(.05))]
    return b"".join(segs)


def build_file_dataset(per_class: int, seed: int = 0):
    rng = np.random.default_rng(seed)
    xs, ys = [], []
    for label, kind in enumerate(FILE_CLASSES):
        for _ in range(per_class):
            xs.append(bytes_to_image(make_file(kind, rng))[None, :, :])
            ys.append(label)
    return np.stack(xs).astype(np.float32), np.array(ys, dtype=np.int64)


# ----------------------------------------------------------------- flows ----
def make_flow(kind: str, rng: np.random.Generator) -> np.ndarray:
    """Return an array of shape (FLOW_LEN, FLOW_CHANNELS) - one row per packet."""
    if kind not in FLOW_CLASSES:
        raise ValueError(f"unknown flow kind: {kind}")
    n = FLOW_LEN
    idx = np.arange(n)
    direction = np.ones(n)

    if kind == "benign":
        size = rng.beta(1.2, 2.0, n)
        direction = np.where(rng.random(n) < 0.6, 1.0, -1.0)
        iat = np.clip(rng.normal(0.45, 0.2, n), 0, 1)
        flag = rng.choice([FLAG_ACK, FLAG_PSH, FLAG_ACK], n) / 5.0
        port = np.full(n, rng.choice([80, 443, 53, 8080, 993]) / 65535.0)
    elif kind == "syn_flood":
        size = np.clip(rng.normal(0.04, 0.005, n), 0, 1)
        iat = np.clip(rng.normal(0.02, 0.01, n), 0, 1)
        flag = np.full(n, FLAG_SYN / 5.0)
        port = np.full(n, rng.choice([80, 443]) / 65535.0)
    elif kind == "port_scan":
        size = np.clip(rng.normal(0.04, 0.005, n), 0, 1)
        direction = np.where(idx % 2 == 0, 1.0, -1.0)
        iat = np.clip(rng.normal(0.08, 0.03, n), 0, 1)
        flag = np.where(idx % 2 == 0, FLAG_SYN, FLAG_RST) / 5.0
        start, step = int(rng.integers(1, 2000)), int(rng.integers(1, 10))
        port = (start + step * (idx // 2)) / 65535.0
    else:  # brute_force
        size = np.clip(rng.normal(0.10, 0.03, n), 0, 1)
        direction = np.where(idx % 2 == 0, 1.0, -1.0)
        iat = np.clip(rng.normal(0.40, 0.02, n), 0, 1)
        flag = rng.choice([FLAG_PSH, FLAG_ACK], n) / 5.0
        port = np.full(n, rng.choice([22, 21, 3389]) / 65535.0)

    flow = np.stack([size, direction, iat, flag, port], axis=1)
    flow[:, [0, 2, 3]] += rng.normal(0, 0.005, (n, 3))
    return flow.astype(np.float32)


def build_flow_dataset(per_class: int, seed: int = 0):
    rng = np.random.default_rng(seed)
    xs, ys = [], []
    for label, kind in enumerate(FLOW_CLASSES):
        for _ in range(per_class):
            xs.append(make_flow(kind, rng).T)  # (channels, length) for Conv1d
            ys.append(label)
    return np.stack(xs).astype(np.float32), np.array(ys, dtype=np.int64)
