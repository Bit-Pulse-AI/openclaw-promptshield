FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash claude && \
    mkdir -p /home/claude/workspace /tmp/openclaw-sandbox /quarantine && \
    chown -R claude:claude /home/claude /tmp/openclaw-sandbox /quarantine

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY openclaw_shield/ /app/openclaw_shield/
COPY config/ /app/config/

# Copy scripts
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Create necessary directories
RUN mkdir -p /var/log/openclaw && \
    chown claude:claude /var/log/openclaw

# Switch to non-root user
USER claude

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port for health checks
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Default command (override in production)
CMD ["python", "-m", "openclaw_shield.main"]
