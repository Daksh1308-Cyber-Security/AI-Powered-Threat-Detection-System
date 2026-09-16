# ===========================================
# Dockerfile: ML Training
# AI-Powered Threat Detection System
# ===========================================
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Default training command.
# Override --data when running datasets outside the default mount.
ENV MODEL_OUTPUT_PATH=/app/models
CMD ["python", "src/train.py", "--data", "/data/labeled_logs.csv", "--model-dir", "/app/models"]