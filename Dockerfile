# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Security: run as unprivileged non-root user
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user
RUN useradd -u 10001 -m -s /bin/bash appuser && \
    mkdir -p /app /home/appuser/.agentblackbox && \
    chown -R appuser:appuser /app /home/appuser

# Copy package requirements & project files
COPY pyproject.toml README.md /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir -e .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/github/healthz || exit 1

CMD ["python", "-m", "agentblackbox", "github-app", "--host", "0.0.0.0", "--port", "8000"]
