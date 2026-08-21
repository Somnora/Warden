# Multi-stage Dockerfile for Warden Operator Control Plane on Google Cloud Run

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build essentials and uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

# Copy project definition
COPY pyproject.toml README.md ./
COPY warden/ warden/

# Install dependencies and project into virtualenv
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache .

# Production runtime stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-root user for security
RUN groupadd -r warden && useradd -r -g warden warden

# Copy installed virtual environment and application code
COPY --from=builder /opt/venv /opt/venv
COPY warden/ warden/
COPY demo.py .

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    WARDEN_MODE=mock \
    WARDEN_MODEL=gemini-3.7-flash \
    WARDEN_CORS_ORIGINS="http://localhost:8000,http://127.0.0.1:8000"

EXPOSE 8080

USER warden

CMD ["uvicorn", "warden.server:app", "--host", "0.0.0.0", "--port", "8080"]
