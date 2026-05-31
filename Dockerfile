# Stage 1: Build
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim
LABEL maintainer="SecureBuild Team"
LABEL description="SecureBuild CI/CD Security Gate"

# Create non-root user
RUN groupadd -r securebuild && useradd -r -g securebuild -m securebuild

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/securebuild/.local
ENV PATH=/home/securebuild/.local/bin:$PATH

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data logs reports && chown -R securebuild:securebuild /app

USER securebuild

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/api/v1/health')" || exit 1

ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
