import numpy as np
import pytest

torch = pytest.importorskip("torch")
from app.cnn.models import FlowCNN, MalwareCNN, grad_cam  # noqa: E402


def test_malware_cnn_shapes_and_gradcam():
    model = MalwareCNN()
    x = torch.rand(2, 1, 64, 64)
    assert model(x).shape == (2, 4)
    cam = grad_cam(model, x[:1], 0)
    assert cam.shape == (8, 8) and 0.0 <= cam.min() and cam.max() <= 1.0


def test_flow_cnn_shapes():
    assert FlowCNN()(torch.rand(3, 5, 16)).shape == (3, 4)
