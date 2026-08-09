FROM python:3.10-slim AS builder

WORKDIR /app

# Install system dependencies required for packet sniffing and building C extensions
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Final stage ---
FROM python:3.10-slim

# Install runtime-only dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin appuser

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy backend source code
COPY . /app/backend

# Create data directory with proper permissions
RUN mkdir -p /app/backend/data/uploads && chown -R appuser:appuser /app

# Switch to non-root user (Upgrade 8)
# NOTE: Packet capture requires NET_RAW capability, which is granted via docker-compose cap_add
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# The command to run the application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
