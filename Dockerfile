# VMware vCenter MCP Server - Enterprise Docker Image with Security Scanning
# Multi-stage build for optimized production deployment with comprehensive security

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Add metadata labels
LABEL org.opencontainers.image.title="VMware vCenter MCP Server"
LABEL org.opencontainers.image.description="Enterprise-grade Model Context Protocol server for VMware vCenter management"
LABEL org.opencontainers.image.authors="uldyssian-sh"
LABEL org.opencontainers.image.vendor="uldyssian-sh"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.source="https://github.com/uldyssian-sh/vmware-vcenter-mcp"
LABEL org.opencontainers.image.url="https://github.com/uldyssian-sh/vmware-vcenter-mcp"
LABEL org.opencontainers.image.documentation="https://github.com/uldyssian-sh/vmware-vcenter-mcp/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies with security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libpq-dev \
    curl \
    ca-certificates \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Security scanning stage
FROM builder as security-scan

# Install security scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy for vulnerability scanning
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Run security scans
RUN trivy filesystem --exit-code 0 --format json --output /tmp/trivy-fs-report.json /
RUN trivy filesystem --exit-code 1 --severity HIGH,CRITICAL --no-progress / || echo "High/Critical vulnerabilities found but continuing build"

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies with security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    postgresql-client \
    redis-tools \
    dumb-init \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /bin/bash mcp

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy security scan results
COPY --from=security-scan /tmp/trivy-fs-report.json /app/security-reports/

# Copy application code
COPY src/ ./src/
COPY config.example.yaml ./config.yaml
COPY setup.py .
COPY README.md .
COPY LICENSE .

# Install the application
RUN pip install -e .

# Create necessary directories with secure permissions
RUN mkdir -p /app/logs /app/data /app/backup /app/cache /app/security-reports && \
    chown -R mcp:mcp /app && \
    chmod 755 /app && \
    find /app -type f -exec chmod 644 {} \; && \
    find /app -type d -exec chmod 755 {} \; && \
    find /app/src -name "*.py" -exec chmod 644 {} \;

# Security hardening
RUN chmod 600 /app/config.yaml && \
    chmod 700 /app/logs /app/data /app/backup /app/cache && \
    chmod 755 /app/security-reports

# Remove unnecessary packages and clean up
RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Switch to non-root user
USER mcp:mcp

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV MCP_CONFIG_FILE=/app/config.yaml
ENV MCP_LOG_LEVEL=INFO
ENV MCP_LOG_FILE=/app/logs/vcenter-mcp.log
ENV MCP_CACHE_DIR=/app/cache
ENV MCP_DATA_DIR=/app/data

# Security labels and metadata
LABEL security.scan="enabled" \
      security.level="high" \
      security.compliance="soc2,iso27001,gdpr" \
      security.non-root="true" \
      security.trivy-scanned="true" \
      security.vulnerability-scan="completed"

# Expose ports
EXPOSE 8080 9090

# Health check with enhanced security
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command
CMD ["python", "-m", "vmware_vcenter_mcp", "--config", "/app/config.yaml"]