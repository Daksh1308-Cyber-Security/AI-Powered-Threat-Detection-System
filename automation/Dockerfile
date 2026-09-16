# ===========================================
# Dockerfile: Alert Triage Automation
# AI-Powered Threat Detection System
# ===========================================
FROM python:3.11-slim

WORKDIR /app

# Triage engine and playbook generator use the standard library only.
COPY alert-triage/ ./alert-triage/
COPY ir-playbook/ ./ir-playbook/
COPY config/ ./config/

EXPOSE 8080

# Minimal stdlib HTTP API for alert triage.
CMD ["python", "alert-triage/api_server.py"]