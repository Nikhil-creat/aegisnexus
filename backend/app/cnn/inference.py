"""Inference facade. Uses the trained CNNs when PyTorch + weights are present,
and otherwise falls back to an explainable entropy/flow heuristic so the rest of
the platform (API, agent, tests, GitHub Pages demo) keeps working."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from .bytemap import GRID, IMG_SIZE, block_entropy_grid, bytes_to_image, pixel_entropy_map, shannon_entropy
from .synthetic import FILE_CLASSES, FLOW_CHANNELS, FLOW_CLASSES, FLOW_LEN

# Prototype (high-entropy fraction, mid-entropy fraction) per class, measured on the synthetic set.
_FILE_PROTOS = {
    "benign": (0.00, 0.03),
    "packed_or_encrypted": (0.98, 0.01),
    "trojan_dropper": (0.35, 0.02),
    "ransomware_like": (0.58, 0.14),
}
_ADMIN_PORTS = {21, 22, 23, 3389, 5900}


def _softmax(v: np.ndarray) -> np.ndarray:
    e = np.exp(v - v.max())
    return e / e.sum()


def heuristic_file_probs(entropy_grid: np.ndarray) -> np.ndarray:
    hi = float((entropy_grid >= 0.90).mean())
    mid = float(((entropy_grid >= 0.70) & (entropy_grid < 0.90)).mean())
    dist = np.array([np.hypot(hi - p[0], mid - p[1]) for p in (_FILE_PROTOS[c] for c in FILE_CLASSES)])
    return _softmax(-20.0 * dist)


def flow_features(seq: np.ndarray) -> dict:
    """seq: (FLOW_LEN, FLOW_CHANNELS) -> interpretable summary features."""
    size, direction, iat, flag, port = (seq[:, i] for i in range(FLOW_CHANNELS))
    ports = np.rint(port * 65535).astype(int)
    return {
        "size_mean": float(size.mean()),
        "dir_mean": float(direction.mean()),
        "dir_flips": float((np.sign(direction[1:]) != np.sign(direction[:-1])).mean()),
        "iat_mean": float(iat.mean()),
        "iat_std": float(iat.std()),
        "flag_mean": float(flag.mean()),
        "unique_ports": int(len(set(ports.tolist()))),
        "port_increasing": float((np.diff(ports) > 0).mean()),
        "admin_port_share": float(np.mean([p in _ADMIN_PORTS for p in ports])),
    }


def heuristic_flow_probs(f: dict) -> np.ndarray:
    syn = 2 * (f["size_mean"] < 0.08) + 2 * (f["dir_mean"] > 0.9) + (f["iat_mean"] < 0.1) + (abs(f["flag_mean"] - 0.2) < 0.05)
    scan = 3 * (f["unique_ports"] >= 6) + 1.5 * (f["port_increasing"] > 0.5) + (f["size_mean"] < 0.08) + (f["dir_flips"] > 0.8)
    brute = 2 * (f["admin_port_share"] > 0.8) + 2 * (f["dir_flips"] > 0.8) + (f["iat_std"] < 0.05) + (0.05 < f["size_mean"] < 0.2)
    scores = np.array([2.0, syn, scan, brute], dtype=float)
    return _softmax(1.2 * scores)


class Detector:
    def __init__(self, model_dir: Path | str = "models") -> None:
        self.model_dir = Path(model_dir)
        self.file_model = None
        self.flow_model = None
        self.metrics: dict = {}
        self._load()

    # ------------------------------------------------------------ loading --
    def _load(self) -> None:
        mpath = self.model_dir / "metrics.json"
        if mpath.exists():
            try:
                self.metrics = json.loads(mpath.read_text())
            except (OSError, ValueError):
                self.metrics = {}
        try:
            import torch
            from .models import FlowCNN, MalwareCNN
        except ImportError:
            return
        for attr, cls, name in (("file_model", MalwareCNN, "malware_cnn.pt"), ("flow_model", FlowCNN, "flow_cnn.pt")):
            path = self.model_dir / name
            if not path.exists():
                continue
            model = cls()
            # weights_only=True: never unpickle arbitrary objects from a weights file.
            model.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
            model.eval()
            setattr(self, attr, model)

    @property
    def file_engine(self) -> str:
        return "torch-cnn" if self.file_model is not None else "entropy-heuristic"

    @property
    def flow_engine(self) -> str:
        return "torch-cnn" if self.flow_model is not None else "flow-heuristic"

    # -------------------------------------------------------------- files --
    def analyze_file(self, data: bytes) -> dict:
        buf = np.frombuffer(data, dtype=np.uint8)
        img = bytes_to_image(data)
        egrid = block_entropy_grid(buf)
        if self.file_model is not None:
            import torch
            from .models import grad_cam
            x = torch.from_numpy(img)[None, None]
            with torch.no_grad():
                probs = torch.softmax(self.file_model(x), dim=1)[0].numpy()
            attention = grad_cam(self.file_model, x, int(probs.argmax()))
            if attention.shape != (GRID, GRID):
                idx = np.linspace(0, attention.shape[0] - 1, GRID).astype(int)
                attention = attention[np.ix_(idx, idx)]
        else:
            probs = heuristic_file_probs(egrid)
            attention = pixel_entropy_map(img)
        k = int(np.argmax(probs))
        return {
            "engine": self.file_engine,
            "label": FILE_CLASSES[k],
            "confidence": round(float(probs[k]), 4),
            "probabilities": {c: round(float(p), 4) for c, p in zip(FILE_CLASSES, probs)},
            "malicious_probability": round(float(1.0 - probs[0]), 4),
            "entropy_bits_per_byte": round(shannon_entropy(buf), 3),
            "size_bytes": int(buf.size),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "attention": [[round(float(v), 3) for v in row] for row in attention],
            "byteplot": {"size": IMG_SIZE, "pixels": (img * 255).astype(int).flatten().tolist()},
        }

    # -------------------------------------------------------------- flows --
    def analyze_flow(self, sequence) -> dict:
        seq = np.asarray(sequence, dtype=np.float32)
        if seq.shape != (FLOW_LEN, FLOW_CHANNELS):
            raise ValueError(f"flow must have shape ({FLOW_LEN}, {FLOW_CHANNELS}), got {tuple(seq.shape)}")
        if not np.isfinite(seq).all():
            raise ValueError("flow contains NaN or infinite values")
        feats = flow_features(seq)
        if self.flow_model is not None:
            import torch
            x = torch.from_numpy(seq.T.copy())[None]
            with torch.no_grad():
                probs = torch.softmax(self.flow_model(x), dim=1)[0].numpy()
        else:
            probs = heuristic_flow_probs(feats)
        k = int(np.argmax(probs))
        return {
            "engine": self.flow_engine,
            "label": FLOW_CLASSES[k],
            "confidence": round(float(probs[k]), 4),
            "probabilities": {c: round(float(p), 4) for c, p in zip(FLOW_CLASSES, probs)},
            "anomaly_probability": round(float(1.0 - probs[0]), 4),
            "features": {k_: round(v, 3) if isinstance(v, float) else v for k_, v in feats.items()},
        }
