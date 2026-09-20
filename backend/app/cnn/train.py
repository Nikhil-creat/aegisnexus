"""Train both CNNs on synthetic data and write weights + metrics.

    python -m app.cnn.train --out models --epochs 8 --samples 300
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn

from .models import FlowCNN, MalwareCNN
from .synthetic import FILE_CLASSES, FLOW_CLASSES, build_file_dataset, build_flow_dataset


def _evaluate(model: nn.Module, x: torch.Tensor, y: torch.Tensor, n_classes: int) -> dict:
    model.eval()
    with torch.no_grad():
        pred = model(x).argmax(1).numpy()
    truth = y.numpy()
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(truth, pred):
        cm[t, p] += 1
    return {"accuracy": round(float((pred == truth).mean()), 4), "confusion": cm.tolist()}


def fit(model: nn.Module, x: np.ndarray, y: np.ndarray, classes: list[str],
        epochs: int, seed: int, batch: int = 64, lr: float = 2e-3) -> dict:
    torch.manual_seed(seed)
    order = np.random.default_rng(seed).permutation(len(x))
    split = int(0.8 * len(x))
    tr, va = order[:split], order[split:]
    xt, yt = torch.from_numpy(x), torch.from_numpy(y)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss()
    history = []
    for ep in range(epochs):
        model.train()
        perm = np.random.default_rng(seed + ep).permutation(tr)
        total = 0.0
        for i in range(0, len(perm), batch):
            b = torch.from_numpy(perm[i:i + batch])
            opt.zero_grad()
            loss = loss_fn(model(xt[b]), yt[b])
            loss.backward()
            opt.step()
            total += float(loss) * len(b)
        val = _evaluate(model, xt[va], yt[va], len(classes))
        history.append({"epoch": ep + 1, "loss": round(total / len(tr), 4), "val_accuracy": val["accuracy"]})
        print(f"  epoch {ep + 1:>2}/{epochs}  loss {history[-1]['loss']:.4f}  val_acc {val['accuracy']:.3f}")
    final = _evaluate(model, xt[va], yt[va], len(classes))
    return {**final, "classes": classes, "history": history, "validation_samples": int(len(va))}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="models")
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--samples", type=int, default=300, help="samples per class")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    print("[1/2] byte-plot CNN (2-D)")
    xf, yf = build_file_dataset(args.samples, args.seed)
    file_model = MalwareCNN()
    file_metrics = fit(file_model, xf, yf, FILE_CLASSES, args.epochs, args.seed)
    torch.save(file_model.state_dict(), out / "malware_cnn.pt")

    print("[2/2] network-flow CNN (1-D)")
    xw, yw = build_flow_dataset(args.samples, args.seed)
    flow_model = FlowCNN()
    flow_metrics = fit(flow_model, xw, yw, FLOW_CLASSES, args.epochs, args.seed)
    torch.save(flow_model.state_dict(), out / "flow_cnn.pt")

    metrics = {
        "trained_on": "synthetic data (see README: Bring your own data)",
        "samples_per_class": args.samples,
        "epochs": args.epochs,
        "seconds": round(time.time() - t0, 1),
        "torch": torch.__version__,
        "file_model": file_metrics,
        "flow_model": flow_metrics,
    }
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"done in {metrics['seconds']}s -> {out.resolve()}")


if __name__ == "__main__":
    main()
