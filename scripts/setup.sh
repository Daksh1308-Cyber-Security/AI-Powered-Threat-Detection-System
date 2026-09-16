#!/bin/bash
# setup.sh
# AI-Powered Threat Detection System
# Linux setup script for ELK Stack and Python environment

set -e

echo "==========================================="
echo " Threat Detection System - Linux Setup"
echo "==========================================="

# Install system dependencies
echo "[*] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    docker.io \
    docker-compose \
    yara \
    yara-python

# Start Docker
echo "[*] Starting Docker..."
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Setup Python virtual environment
echo "[*] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r ml-model/requirements.txt

# Install sigma-cli
echo "[*] Installing Sigma CLI..."
pip install sigma-cli

# Install yara-python
echo "[*] Installing YARA Python bindings..."
pip install yara-python

# Setup Elasticsearch configuration
echo "[*] Setting up Elasticsearch..."
if ! sysctl vm.max_map_count > /dev/null 2>&1; then
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
fi

# Copy environment file
echo "[*] Creating environment file..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    # Generate encryption keys
    sed -i "s/your-32-byte-hex-encryption-key-here/$(openssl rand -hex 32)/" .env
    sed -i "s/your-32-byte-hex-reporting-key-here/$(openssl rand -hex 32)/" .env
fi

# Test Docker Compose
echo "[*] Testing Docker Compose..."
docker-compose config --quiet

echo ""
echo "==========================================="
echo " Setup Complete!"
echo "==========================================="
echo ""
echo "Next steps:"
echo "  1. Start ELK stack: docker-compose up -d"
echo "  2. Wait 2-3 minutes for Elasticsearch"
echo "  3. Access Kibana: http://localhost:5601"
echo "  4. Generate dataset: python scripts/generate-dataset.py --records 50000"
echo "  5. Train model: python ml-model/src/train.py --data lab/datasets/labeled_logs.csv"
echo "  6. Launch dashboard: cd dashboards/soc-dashboard && streamlit run app.py"
echo ""
echo "Note: You may need to log out and back in for Docker group changes."