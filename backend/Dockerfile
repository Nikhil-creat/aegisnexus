# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv

# CPU-only PyTorch keeps the image small; the rest comes from requirements.txt
RUN pip install torch==2.3.1 --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Train the CNNs at build time (synthetic data, ~1-3 min on CPU) so the image is self-contained.
ARG TRAIN_EPOCHS=8
ARG TRAIN_SAMPLES=300
RUN python -m app.cnn.train --out /srv/models --epochs ${TRAIN_EPOCHS} --samples ${TRAIN_SAMPLES}

# Run as an unprivileged user
RUN useradd --system --uid 10001 --no-create-home aegis && mkdir -p /srv/data && chown -R aegis /srv
USER aegis
ENV MODEL_DIR=/srv/models DB_PATH=/srv/data/aegis.db
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
