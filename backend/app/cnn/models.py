"""PyTorch models: a 2-D CNN for byte-plot images and a 1-D CNN for packet flows."""
from __future__ import annotations

import numpy as np
import torch
from torch import nn

from .synthetic import FILE_CLASSES, FLOW_CHANNELS, FLOW_CLASSES


def _conv_block(cin: int, cout: int, pool: bool = True) -> nn.Sequential:
    layers = [nn.Conv2d(cin, cout, 3, padding=1), nn.BatchNorm2d(cout), nn.ReLU(inplace=True)]
    if pool:
        layers.append(nn.MaxPool2d(2))
    return nn.Sequential(*layers)


class MalwareCNN(nn.Module):
    """Input (B, 1, 64, 64) -> logits (B, n_classes). Final feature map is 8x8 (used by Grad-CAM)."""

    def __init__(self, n_classes: int = len(FILE_CLASSES)) -> None:
        super().__init__()
        self.features = nn.Sequential(
            _conv_block(1, 16), _conv_block(16, 32), _conv_block(32, 64),
            _conv_block(64, 128, pool=False),
        )
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.classifier = nn.Sequential(nn.Flatten(), nn.Dropout(0.3), nn.Linear(128, n_classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.pool(self.features(x)))


class FlowCNN(nn.Module):
    """Input (B, 5 channels, 16 packets) -> logits (B, n_classes)."""

    def __init__(self, in_ch: int = FLOW_CHANNELS, n_classes: int = len(FLOW_CLASSES)) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv1d(in_ch, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU(inplace=True),
            nn.Conv1d(32, 64, 3, padding=1), nn.BatchNorm1d(64), nn.ReLU(inplace=True),
            nn.MaxPool1d(2),
            nn.Conv1d(64, 64, 3, padding=1), nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool1d(1), nn.Flatten(), nn.Dropout(0.2), nn.Linear(64, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def grad_cam(model: MalwareCNN, x: torch.Tensor, target: int) -> np.ndarray:
    """Grad-CAM heat-map (h, w) in [0, 1]: which regions of the byte-plot drove the decision."""
    model.eval()
    with torch.enable_grad():
        fmap = model.features(x)
        fmap.retain_grad()
        logits = model.classifier(model.pool(fmap))
        model.zero_grad(set_to_none=True)
        logits[0, target].backward()
        weights = fmap.grad.mean(dim=(2, 3), keepdim=True)
        cam = torch.relu((weights * fmap).sum(dim=1)).squeeze(0)
    cam = cam.detach().cpu().numpy()
    peak = float(cam.max())
    return cam / peak if peak > 1e-8 else np.zeros_like(cam)
