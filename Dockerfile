FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
COPY packages ./packages
COPY scripts ./scripts

RUN uv sync --all-packages

ENV PATH="/app/.venv/bin:${PATH}"

# Default identity home inside containers
ENV YAKR_HOME=/data

CMD ["yakr", "--help"]
